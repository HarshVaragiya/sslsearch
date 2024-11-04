package cmd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HarshVaragiya/jarm-go"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func PerformPreRunChecks(checkRegion bool) {
	CheckInputParameters()
	UpdateLogLevel()
	PerformOutputChecks()
	if checkRegion {
		CheckRegionRegex()
	}
	log.WithFields(logrus.Fields{"state": "main"}).Debugf("sanity checks passed")
}

func CheckInputParameters() {
	if _, err := regexp.Compile("(?i)" + keywordRegexString); err != nil {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("could not compile keyword regex")
	}
}

func CheckRegionRegex() {
	if _, err := regexp.Compile(regionRegexString); err != nil {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("could not compile region regex")
	}
}

func getRecordKey() string {
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02")
	return formattedTime
}

func UpdateLogLevel() {
	if debugFlag {
		log.SetLevel(logrus.DebugLevel)
		log.WithFields(logrus.Fields{"state": "main"}).Debugf("enabled debug logging")
	}
}

func PerformOutputChecks() {
	if !diskExport && !elasticsearchExport && !cassandraExport {
		log.WithFields(logrus.Fields{"state": "checks"}).Fatal("export target disk / cassandra / elasticsearch must be configured")
	}
	if diskExport && diskFilePath != "" {
		if _, err := os.Stat(diskFilePath); err == nil {
			log.WithFields(logrus.Fields{"state": "checks"}).Fatal("output file already exists!")
		} else if errors.Is(err, os.ErrNotExist) {
			log.WithFields(logrus.Fields{"state": "checks"}).Debugf("output file does not exist and will be created")
		}
	}
	if cassandraExport && cassandraConnectionString != "" && cassandraRecordTimeStampKey == "" {
		cassandraRecordTimeStampKey = getRecordKey()
		log.WithFields(logrus.Fields{"state": "checks"}).Infof("cassandra output record key: %s", cassandraRecordTimeStampKey)
	}
	if elasticsearchExport && elasticsearchHost != "" && elasticsearchIndex == "" {
		elasticsearchIndex = fmt.Sprintf("sslsearch-%s", getRecordKey())
		log.WithFields(logrus.Fields{"state": "checks"}).Infof("elasticsearch output index: %s", elasticsearchIndex)
	}
}

func ScanCloudServiceProvider(ctx context.Context, csp string, cloudServiceProvider CidrRangeInput) {
	cidrChan := make(chan CidrRange, threadCount*5)
	cspCidrChan := make(chan CidrRange, threadCount*2)

	go func() {
		cloudServiceProvider.GetCidrRanges(ctx, cspCidrChan, regionRegexString)
	}()
	go func() {
		defer close(cidrChan)
		for {
			select {
			case <-ctx.Done():
				log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "csp": csp}).Info("context done")
				return
			case cspCidr, open := <-cspCidrChan:
				if !open {
					log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "csp": csp}).Info("done generating sub cidr ranges")
					return
				}
				if err := SplitCIDR(cspCidr, cidrSuffixPerGoRoutine, cidrChan); err != nil {
					log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "errmsg": err.Error(), "csp": csp}).Fatal("error generating sub-CIDR ranges")
				}
			}
		}
	}()
	RunScan(cidrChan)
}

func RunScan(cidrChan chan CidrRange) {
	ports := strings.Split(portsString, ",")
	log.WithFields(logrus.Fields{"state": "main"}).Infof("ports to be scanned: %s", ports)
	resultChan := make(chan *CertResult, threadCount*8)

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// handle interrupt (Ctrl + C)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT)
	go func() {
		s := <-signals
		log.WithFields(logrus.Fields{"state": "main"}).Infof("received %v ... cancelling context.", s.String())
		log.WithFields(logrus.Fields{"state": "main"}).Infof("waiting for threads to exit ...")
		cancelFunc()
		fmt.Printf("\n\n\n\n\n\n")
		s = <-signals
		log.WithFields(logrus.Fields{"state": "main"}).Fatalf("forcing exit due to %v", s.String())
	}()

	// start scanning
	startTime := time.Now()
	log.WithFields(logrus.Fields{"state": "main"}).Info("starting scanner threads")
	scanWg := &sync.WaitGroup{}
	scanWg.Add(threadCount)
	for i := 0; i < threadCount; i++ {
		go ScanCertificatesInCidr(ctx, cidrChan, ports, resultChan, scanWg, keywordRegexString)
	}

	serverHeaderWg := &sync.WaitGroup{}
	headerEnrichedResultsChan := ServerHeaderEnrichment(ctx, resultChan, serverHeaderThreadCount, serverHeaderWg)
	jarmFingerprintWg := &sync.WaitGroup{}
	enrichedResultChan := JARMFingerprintEnrichment(ctx, headerEnrichedResultsChan, jarmFingerprintThreadCount, jarmFingerprintWg)

	// export results
	resultWg := &sync.WaitGroup{}
	resultWg.Add(1)
	exportTarget := GetExportTarget()
	go exportTarget.Export(enrichedResultChan, resultWg)

	if consoleProgressLog {
		go PrintProgressToConsole(consoleRefreshSeconds)
	} else {
		go ProgressBar(consoleRefreshSeconds)
	}

	// wait for tls scanning to finish
	state = 1
	log.WithFields(logrus.Fields{"state": "main"}).Info("waiting for tls scanner threads to finish scanning")
	scanWg.Wait()
	close(resultChan)

	// wait for enrichment to finish
	state = 2
	log.WithFields(logrus.Fields{"state": "main"}).Info("waiting for server header enrichment threads to finish")
	serverHeaderWg.Wait()
	close(headerEnrichedResultsChan)
	log.WithFields(logrus.Fields{"state": "main"}).Info("server header enrichment threads finished")

	state = 3
	log.WithFields(logrus.Fields{"state": "main"}).Infof("waiting for jarm fingerprint enrichment threads to finish")
	jarmFingerprintWg.Wait()
	close(enrichedResultChan)
	log.WithFields(logrus.Fields{"state": "main"}).Info("jarm fingerprint enrichment threads finished")

	// wait for export to finish
	state = 4
	log.WithFields(logrus.Fields{"state": "main"}).Info("waiting for export threads to finish")
	resultWg.Wait()
	log.WithFields(logrus.Fields{"state": "main"}).Info("done exporting to target")

	state = 5
	stopTime := time.Now()
	Summarize(startTime, stopTime)
}

func GetCspInstance(cspString string) (CidrRangeInput, error) {
	cspString = strings.ToLower(cspString)
	if cspString == "aws" {
		return AWS{}, nil
	} else if cspString == "gcp" {
		return GCP{}, nil
	} else if cspString == "oracle" {
		return Oracle{}, nil
	} else if cspString == "digital-ocean" {
		return DigitalOcean{}, nil
	} else if cspString == "cloudflare" {
		return Cloudflare{}, nil
	}
	return nil, fmt.Errorf("unknown cloud service provider")
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func getRemoteAddrString(ip, port string) string {
	return fmt.Sprintf("%v:%v", ip, port)
}

func SplitCIDR(cidrString CidrRange, suffixLenPerGoRoutine int, cidrChan chan CidrRange) error {
	cidr := ipaddr.NewIPAddressString(cidrString.Cidr).GetAddress()
	cidrRange := cidr.GetPrefixLen().Len()
	adjustPrefixLength := 32 - cidrRange - suffixLenPerGoRoutine
	if adjustPrefixLength < 0 {
		adjustPrefixLength = 0
	}
	for i := cidr.AdjustPrefixLen(adjustPrefixLength).PrefixBlockIterator(); i.HasNext(); {
		nextCidr := i.Next()
		cidrChan <- CidrRange{Cidr: nextCidr.String(), CSP: cidrString.CSP, Region: cidrString.Region}
		log.WithFields(logrus.Fields{"state": "split-cidr"}).Debugf("added cidr range %s for scanning", nextCidr)
		cidrRangesToScan.Add(1)
		ipsToScan.Add(int64(math.Pow(2, float64(32-nextCidr.GetPrefixLen().Len()))))
	}
	return nil
}

func headerEnrichmentThread(ctx context.Context, rawResultChan, enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
	defer wg.Done()
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debug("server header enrichment thread starting")
	for rawResult := range rawResultChan {
		serverHeader, allHeaders, err := GrabServerHeaderForRemote(getRemoteAddrString(rawResult.Ip, rawResult.Port))
		if err == nil {
			serverHeadersGrabbed.Add(1)
		}
		if val, ok := allHeaders["Host"]; ok {
			rawResult.Host = val
		}
		rawResult.Server = serverHeader
		rawResult.Headers = allHeaders
		serverHeadersScanned.Add(1)
		enrichedResultChan <- rawResult
	}
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debugf("server header enrichment thread exiting")
}

func jarmFingerprintEnrichmentThread(ctx context.Context, rawResultChan, enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
	defer wg.Done()
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debug("JARM Fingerprint enrichment thread exiting")
	for rawResult := range rawResultChan {
		if jarmFingerprint, err := GetJARMFingerprint(getRemoteAddrString(rawResult.Ip, rawResult.Port)); err == nil {
			rawResult.JARM = jarmFingerprint
			jarmFingerprintsGrabbed.Add(1)
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": getRemoteAddrString(rawResult.Ip, rawResult.Port)}).Debugf("JARM Fingerprint: %v", jarmFingerprint)
		} else {
			rawResult.JARM = jarmFingerprint
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": getRemoteAddrString(rawResult.Ip, rawResult.Port), "errmsg": err.Error()}).Tracef("JARM Fingerprint: %v ", jarmFingerprint)
		}
		jarmFingerprintsScanned.Add(1)
		enrichedResultChan <- rawResult
	}
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debugf("JARM Fingerprint enrichment thread exiting")
}

func GrabServerHeaderForRemote(remote string) (string, map[string]string, error) {
	client := httpClientPool.Get().(*fasthttp.Client)
	defer httpClientPool.Put(client)
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(fmt.Sprintf("https://%s", remote))
	err := client.Do(req, resp)
	allHeaders := make(map[string]string)
	if err != nil {
		return "", allHeaders, err
	}
	resp.Header.EnableNormalizing()
	resp.Header.VisitAll(func(key, value []byte) {
		allHeaders[string(key)] = string(value)
	})
	return string(resp.Header.Peek("Server")), allHeaders, nil
}

func GetJARMFingerprint(remote string) (string, error) {
	host, port := SplitRemoteAddr(remote)
	target := jarm.Target{
		Host:    host,
		Port:    port,
		Retries: jarmRetryCount,
	}
	res, err := jarm.Fingerprint(target)
	if res == nil {
		return "", err
	}
	if err == nil {
		return res.Hash, res.Error
	}
	return res.Hash, err
}

func SplitRemoteAddr(remote string) (host string, port int) {
	s := strings.Split(remote, ":")
	host = s[0]
	port, _ = strconv.Atoi(s[1])
	return
}

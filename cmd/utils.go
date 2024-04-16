package cmd

import (
	"context"
	"errors"
	"fmt"
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
	log.WithFields(logrus.Fields{"state": "main"}).Info("sanity check passed")
}

// perform sanity check on inputs
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

func UpdateLogLevel() {
	if traceFlag {
		log.SetLevel(logrus.TraceLevel)
		log.WithFields(logrus.Fields{"state": "main"}).Info("enabled trace logging")
	} else if debugFlag {
		log.SetLevel(logrus.DebugLevel)
		log.WithFields(logrus.Fields{"state": "main"}).Info("enabled debug logging")
	}
}

func PerformOutputChecks() {
	if outFileName == "" && cassandraConnectionString == "" {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("output file / cassandra connection string must be supplied!")
	}
	if outFileName != "" {
		if _, err := os.Stat(outFileName); err == nil {
			log.WithFields(logrus.Fields{"state": "main"}).Fatal("output file already exists!")
		} else if errors.Is(err, os.ErrNotExist) {
			log.WithFields(logrus.Fields{"state": "main"}).Debugf("output file does not exist and will be created")
		}
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
	resultChan := make(chan *CertResult, threadCount*2)
	var enrichedResultChan chan *CertResult
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
		s = <-signals
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("forcing exit due to %v", s.String())
	}()

	// log results to disk
	log.WithFields(logrus.Fields{"state": "main"}).Infof("saving output to: %v", outFileName)
	outFile, err := os.OpenFile(outFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.WithFields(logrus.Fields{"state": "main", "errmsg": err.Error()}).Fatalf("could not open output file for writing")
	}
	defer outFile.Close()

	// start scanning
	startTime := time.Now()
	log.WithFields(logrus.Fields{"state": "main"}).Info("starting scanner threads")
	scanWg := &sync.WaitGroup{}
	scanWg.Add(threadCount)
	for i := 0; i < threadCount; i++ {
		go ScanCertificatesInCidr(ctx, cidrChan, ports, resultChan, scanWg, keywordRegexString)
	}

	// start enrichment threads in the background with given options
	enrichWg := &sync.WaitGroup{}
	enrichedResultChan = resultChan
	if grabServerHeader {
		enrichWg.Add(1)
		serverHeaderWg := &sync.WaitGroup{}
		enrichedResultChan = ServerHeaderEnrichment(ctx, enrichedResultChan, serverHeaderThreadCount, serverHeaderWg)
		go func(enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
			wg.Wait()
			close(enrichedResultChan)
			enrichWg.Done()
		}(enrichedResultChan, serverHeaderWg)
	}
	if grabJarmFingerprint {
		enrichWg.Add(1)
		jarmFingerprintWg := &sync.WaitGroup{}
		enrichedResultChan = JARMFingerprintEnrichment(ctx, enrichedResultChan, jarmFingerptintThreadCount, jarmFingerprintWg)
		go func(enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
			wg.Wait()
			close(enrichedResultChan)
			enrichWg.Done()
		}(enrichedResultChan, jarmFingerprintWg)
	}

	// save results to disk
	resultWg := &sync.WaitGroup{}
	resultWg.Add(1)
	go SaveResultsToDisk(enrichedResultChan, resultWg, outFile, consoleOut)
	go PrintProgressToConsole(consoleRefreshMs)

	// wait for everything to finish!
	log.WithFields(logrus.Fields{"state": "main"}).Info("waiting for threads to finish scanning")
	scanWg.Wait()
	stopTime := time.Now()
	close(resultChan)

	// enrichment
	log.WithFields(logrus.Fields{"state": "main"}).Info("waiting for enrichment threads to finish")
	enrichWg.Wait()
	log.WithFields(logrus.Fields{"state": "main"}).Info("enrichment threads finished")

	// save results to disk
	log.WithFields(logrus.Fields{"state": "main"}).Info("saving results to disk ...")
	resultWg.Wait()
	log.WithFields(logrus.Fields{"state": "main"}).Info("done writing results to disk")

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
		nextCidr := i.Next().String()
		statsLock.Lock()
		cidrRangesToScan += 1
		statsLock.Unlock()
		cidrChan <- CidrRange{Cidr: nextCidr, CSP: cidrString.CSP, Region: cidrString.Region}
	}
	return nil
}

func ServerHeaderEnrichmentThread(ctx context.Context, rawResultChan, enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
	defer wg.Done()
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debug("server header enrichment thread starting")
	for rawResult := range rawResultChan {
		if header, err := GrabServerHeaderForRemote(rawResult.RemoteAddr); err == nil {
			rawResult.ServerHeader = header
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": rawResult.RemoteAddr}).Debugf("Server: %v", header)
		} else {
			rawResult.ServerHeader = header
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": rawResult.RemoteAddr, "errmsg": err.Error()}).Tracef("Server: %v ", header)
		}
		enrichedResultChan <- rawResult
	}
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debug("server header enrichment thread exiting")
}

func JarmFingerprintEnrichmentThread(ctx context.Context, rawResultChan, enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
	defer wg.Done()
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debug("JARM Fingerprint enrichment thread exiting")
	for rawResult := range rawResultChan {
		if jarmFingerprint, err := GetJARMFingerprint(rawResult.RemoteAddr); err == nil {
			rawResult.JARM = jarmFingerprint
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": rawResult.RemoteAddr}).Debugf("JARM Fingerprint: %v", jarmFingerprint)
		} else {
			rawResult.JARM = jarmFingerprint
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": rawResult.RemoteAddr, "errmsg": err.Error()}).Tracef("JARM Fingerprint: %v ", jarmFingerprint)
		}
		enrichedResultChan <- rawResult
	}
	log.WithFields(logrus.Fields{"state": "enrichment"}).Debug("JARM Fingerprint enrichment thread exiting")
}

func GrabServerHeaderForRemote(remote string) (string, error) {
	client := httpClientPool.Get().(*fasthttp.Client)
	defer httpClientPool.Put(client)
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(fmt.Sprintf("https://%s", remote))
	err := client.Do(req, resp)
	if err != nil {
		return "", err
	}
	return string(resp.Header.Peek("Server")), nil
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

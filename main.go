package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	logrus "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

const (
	TOTAL_IPv4_ADDR_COUNT = 3706452992
)

var (
	log               = logrus.New()
	statsLock         = sync.RWMutex{}
	cidrRangesToScan  = 0
	cidrRangesScanned = 0
	totalIpsScanned   = 0
	totalFindings     = 0
	jarmRetryCount    = 3

	tcpTimeout = 10

	httpClientPool = sync.Pool{
		New: func() interface{} {
			return &fasthttp.Client{
				TLSConfig: &tls.Config{
					// for server header check skip SSL validation
					InsecureSkipVerify: true,
				},
			}
		},
	}
	dialerPool = sync.Pool{
		New: func() interface{} {
			return &net.Dialer{
				Timeout: time.Duration(tcpTimeout) * time.Second,
			}
		},
	}
	tlsConfigPool = sync.Pool{
		New: func() interface{} {
			return &tls.Config{
				InsecureSkipVerify: true,
			}
		},
	}
	errConn              = fmt.Errorf("could not connect to remote host")
	errNoTls             = fmt.Errorf("could not find TLS on remote port")
	errNoMatch           = fmt.Errorf("certificate details did not match requirement")
	errCtxCancelled      = fmt.Errorf("parent context cancelled")
	errJarmNotCalculated = fmt.Errorf("error calculating JARM fingerprint")
)

func ScanCertificatesInCidr(ctx context.Context, cidrChan chan string, ports []string, resultChan chan *CertResult, wg *sync.WaitGroup, keywordRegexString string) {
	defer wg.Done()
	keywordRegex := regexp.MustCompile(keywordRegexString)
	for {
		select {
		case <-ctx.Done():
			log.WithFields(logrus.Fields{"state": "scan"}).Tracef("context done")
			return
		case cidr, open := <-cidrChan:
			if !open {
				return
			}
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.WithFields(logrus.Fields{"state": "scan", "errmsg": err.Error(), "cidr": cidr}).Errorf("failed to parse CIDR")
				continue
			}
			log.WithFields(logrus.Fields{"state": "scan", "cidr": cidr}).Debugf("starting scan for CIDR range")
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				for _, port := range ports {
					remote := getRemoteAddrString(ip.String(), port)
					result, err := ScanRemote(ctx, remote, keywordRegex)
					if err != nil {
						log.WithFields(logrus.Fields{"state": "deepscan", "remote": remote, "errmsg": err.Error()}).Tracef("error")
						continue
					} else {
						resultChan <- result
					}
				}
			}
			statsLock.Lock()
			cidrRangesScanned += 1
			statsLock.Unlock()
		}
	}
}

func ScanRemote(ctx context.Context, remote string, keywordRegex *regexp.Regexp) (*CertResult, error) {
	log.WithFields(logrus.Fields{"state": "deepscan", "remote": remote}).Tracef("scanning")
	select {
	case <-ctx.Done():
		return nil, errCtxCancelled
	default:
		dialer := dialerPool.Get().(*net.Dialer)
		defer dialerPool.Put(dialer)
		tlsConfig := tlsConfigPool.Get().(*tls.Config)
		defer tlsConfigPool.Put(tlsConfig)
		conn, err := tls.DialWithDialer(dialer, "tcp", remote, tlsConfig)
		statsLock.Lock()
		defer statsLock.Unlock()
		totalIpsScanned += 1
		if err != nil {
			return nil, errConn
		}
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			return nil, errNoTls
		}
		subjectMatch := keywordRegex.MatchString(certs[0].Subject.String())
		sanMatch := keywordRegex.MatchString(fmt.Sprintf("%s", certs[0].DNSNames))
		log.WithFields(logrus.Fields{"state": "deepscan", "remote": remote, "subject": certs[0].Subject.String(), "match": subjectMatch || sanMatch}).Debugf("SANs: %s ", certs[0].DNSNames)
		if subjectMatch || sanMatch {
			totalFindings += 1
			return &CertResult{
				RemoteAddr: remote,
				Subject:    certs[0].Subject.CommonName,
				Issuer:     certs[0].Issuer.CommonName,
				SANs:       certs[0].DNSNames,
			}, nil
		}
		return nil, errNoMatch
	}
}

func main() {
	// main input flags
	cspString := flag.String("csp", "", "cloud service provider to search (ex: AWS,GCP)")
	ipCidr := flag.String("cidr", "", "IPv4 CIDR range to search (ex: 192.168.0.0/24)")

	// refined input flags
	keywordRegexString := flag.String("keyword-regex", ".*", "keyword regex to search in subject or SAN (ex: amazon,google). Default .* which matches all")
	regionRegexString := flag.String("region-regex", ".*", "regex of cloud service provider region to search. (best effort basis as cloudflare does not provide region)")
	portsString := flag.String("ports", "443", "ports to search (default: 443)")
	outfileName := flag.String("out", "output.log", "output file on disk")
	outputOverwrite := flag.Bool("overwrite", false, "overwrite output file if it exists")
	threadCount := flag.Int("threads", 2000, "number of parallel threads to use")

	// advanced input flags
	cidrSuffixPerGoRoutine := flag.Int("suffix", 4, "CIDR suffix per goroutine (each thread will scan 2^x IPs. default 4)")
	debug := flag.Bool("debug", false, "enable debug logs")
	trace := flag.Bool("trace", false, "enable trace logs")
	tcpTimeoutFlag := flag.Int("timeout", 10, "tcp connection timeout in seconds")
	consoleOut := flag.Bool("console-out", false, "prints result JSON to console for debugging")

	// advanced enrichment flags
	grabServerHeader := flag.Bool("server-header", false, "attempt enrich results by grabbing the https server header for results")
	grabJarmFingerprint := flag.Bool("jarm", false, "attempt enrich results by grabbing the JARM fingerprint")
	jarmRetryCountFlag := flag.Int("jarm-retry-count", 3, "retry attempts for JARM fingerprint (default 3)")
	serverHeaderThreadCount := flag.Int("server-header-threads", 10, "number of threads to use for server header result enrichment")
	jarmFingerptintThreadCount := flag.Int("jarm-threads", 50, "number of threads to use for JARM fingerprint enrichment")

	flag.Parse()

	// sanity check on input
	if *cspString == "" && *ipCidr == "" {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("either -cidr or -csp must be provided")
	}
	if _, err := regexp.Compile(*keywordRegexString); err != nil {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("could not compile keyword regex")
	}
	if _, err := regexp.Compile(*regionRegexString); err != nil {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("could not compile region regex")
	}
	log.WithFields(logrus.Fields{"state": "main"}).Info("input passed sanity checks")

	// debug configuration
	if *trace {
		log.SetLevel(logrus.TraceLevel)
		log.WithFields(logrus.Fields{"state": "main"}).Info("enabled trace logging")
	} else if *debug {
		log.SetLevel(logrus.DebugLevel)
		log.WithFields(logrus.Fields{"state": "main"}).Info("enabled debug logging")
	}

	// check if output file already exists or not
	if _, err := os.Stat(*outfileName); err == nil {
		if *outputOverwrite {
			log.WithFields(logrus.Fields{"state": "main"}).Info("overwriting existing output file in 5 seconds")
			time.Sleep(5 * time.Second)
		} else {
			log.WithFields(logrus.Fields{"state": "main"}).Fatal("output file exists & overwrite flag not supplied!")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		log.WithFields(logrus.Fields{"state": "main"}).Debugf("output file does not exist and will be created")
	}

	tcpTimeout = *tcpTimeoutFlag
	jarmRetryCount = *jarmRetryCountFlag

	// variables
	ports := strings.Split(*portsString, ",")
	log.WithFields(logrus.Fields{"state": "main"}).Infof("parsed ports to scan: %s", ports)
	cidrChan := make(chan string, *threadCount*5)
	resultChan := make(chan *CertResult, *threadCount*2)
	var enrichedResultChan chan *CertResult
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// handle interrupt (Ctrl + C)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT)
	go func() {
		s := <-signals
		log.WithFields(logrus.Fields{"state": "main"}).Infof("received %v ... cancelling context.", s.String())
		log.WithFields(logrus.Fields{"state": "main"}).Infof("waiting for threads to exit ... do not force exit right now!")
		cancelFunc()
		s = <-signals
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("forcing exit due to %v", s.String())
	}()

	// for CSP scanning
	if *cspString != "" {
		cspCidrChan := make(chan string, *threadCount*2)
		cloudServiceProvider, err := GetCspInstance(*cspString)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "main"}).Fatal(err)
		}
		go func() {
			cloudServiceProvider.GetCidrRanges(ctx, cspCidrChan, *regionRegexString)
		}()
		go func() {
			defer close(cidrChan)
			for {
				select {
				case <-ctx.Done():
					log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "csp": *cspString}).Info("context done")
					return
				case cspCidr, open := <-cspCidrChan:
					if !open {
						log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "csp": *cspString}).Info("done generating sub cidr ranges")
						return
					}
					if err := SplitCIDR(cspCidr, *cidrSuffixPerGoRoutine, cidrChan); err != nil {
						log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "errmsg": err.Error(), "csp": *cspString}).Fatal("error generating sub-CIDR ranges")
					}
				}
			}
		}()
	}

	// for CIDR scanning
	if *ipCidr != "" {
		go func() {
			defer close(cidrChan)
			err := SplitCIDR(*ipCidr, *cidrSuffixPerGoRoutine, cidrChan)
			if err != nil {
				log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "errmsg": err.Error(), "cidr": *ipCidr}).Fatal("error generating sub-CIDR ranges")
			}
		}()
	}

	// log results to disk
	log.WithFields(logrus.Fields{"state": "main"}).Infof("saving output to: %v", *outfileName)
	outFile, err := os.OpenFile(*outfileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.WithFields(logrus.Fields{"state": "main", "errmsg": err.Error()}).Fatalf("could not open output file for writing")
	}
	defer outFile.Close()

	// start scanning
	startTime := time.Now()
	log.WithFields(logrus.Fields{"state": "main"}).Info("starting scanner threads")
	scanWg := &sync.WaitGroup{}
	scanWg.Add(*threadCount)
	for i := 0; i < *threadCount; i++ {
		go ScanCertificatesInCidr(ctx, cidrChan, ports, resultChan, scanWg, *keywordRegexString)
	}

	// start enrichment threads in the background with given options
	enrichWg := &sync.WaitGroup{}
	enrichedResultChan = resultChan
	if *grabServerHeader {
		enrichWg.Add(1)
		serverHeaderWg := &sync.WaitGroup{}
		enrichedResultChan = ServerHeaderEnrichment(ctx, enrichedResultChan, *serverHeaderThreadCount, serverHeaderWg)
		go func(enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
			wg.Wait()
			close(enrichedResultChan)
			enrichWg.Done()
		}(enrichedResultChan, serverHeaderWg)
	}
	if *grabJarmFingerprint {
		enrichWg.Add(1)
		jarmFingerprintWg := &sync.WaitGroup{}
		enrichedResultChan = JARMFingerprintEnrichment(ctx, enrichedResultChan, *jarmFingerptintThreadCount, jarmFingerprintWg)
		go func(enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
			wg.Wait()
			close(enrichedResultChan)
			enrichWg.Done()
		}(enrichedResultChan, jarmFingerprintWg)
	}

	// save results to disk
	resultWg := &sync.WaitGroup{}
	resultWg.Add(1)
	go SaveResultsToDisk(enrichedResultChan, resultWg, outFile, *consoleOut)
	go PrintProgressToConsole(2000)

	// wait for everything to finish!
	log.WithFields(logrus.Fields{"state": "main"}).Info("waiting for threads to finish scanning")
	scanWg.Wait()
	stopTime := time.Now()
	close(resultChan)

	// enrichment
	log.WithFields(logrus.Fields{"state": "main"}).Info("waiting for enrichment threads to finish")
	enrichWg.Wait()
	log.WithFields(logrus.Fields{"state": "main"}).Info("enrichment threads finished")
	// if _, open := <-enrichedResultChan; open {
	// 	// close enrichment channel only if it is open
	// 	close(enrichedResultChan)
	// }

	// save results to disk
	log.WithFields(logrus.Fields{"state": "main"}).Info("saving results to disk ...")
	resultWg.Wait()
	log.WithFields(logrus.Fields{"state": "main"}).Info("done writing results to disk")

	Summarize(startTime, stopTime)
}

func Summarize(start, stop time.Time) {
	statsLock.Lock()
	defer statsLock.Unlock()
	elapsedTime := stop.Sub(start)
	percentage := float64(totalIpsScanned) / TOTAL_IPv4_ADDR_COUNT
	fmt.Printf("Total IPs Scanned           : %v (%v %% of the internet)\n", totalIpsScanned, percentage)
	fmt.Printf("Total Findings              : %v \n", totalFindings)
	fmt.Printf("Total CIDR ranges Scanned   : %v \n", cidrRangesScanned)
	fmt.Printf("Time Elapsed                : %v \n", elapsedTime)
	fmt.Printf("Scan Speed                  : %v IPs/second \n", (1000000000*totalIpsScanned)/int(elapsedTime))
}

func SaveResultsToDisk(resultChan chan *CertResult, resultWg *sync.WaitGroup, outFile *os.File, consoleout bool) {
	defer resultWg.Done()
	enc := json.NewEncoder(outFile)
	for result := range resultChan {
		if err := enc.Encode(result); err != nil {
			log.WithFields(logrus.Fields{"state": "save", "subject": result.Subject, "SANs": fmt.Sprintf("%s", result.SANs)}).Error("error saving result to disk")
		}
		if consoleout {
			log.WithFields(logrus.Fields{"state": "save", "subject": result.Subject, "SANs": fmt.Sprintf("%s", result.SANs), "jarm": result.JARM, "server": result.ServerHeader}).Info(result.RemoteAddr)
		} else {
			log.WithFields(logrus.Fields{"state": "save", "subject": result.Subject, "SANs": fmt.Sprintf("%s", result.SANs), "jarm": result.JARM, "server": result.ServerHeader}).Debug(result.RemoteAddr)
		}
	}
}

func PrintProgressToConsole(refreshInterval int) {
	for {
		statsLock.RLock()
		fmt.Printf("Progress: CIDRs [ %v / %v ]  Findings: %v, TotalIPs Scanned : %v           \r", cidrRangesScanned, cidrRangesToScan, totalFindings, totalIpsScanned)
		statsLock.RUnlock()
		time.Sleep(time.Millisecond * time.Duration(int64(refreshInterval)))
	}
}

func ServerHeaderEnrichment(ctx context.Context, rawResultChan chan *CertResult, enrichmentThreads int, wg *sync.WaitGroup) chan *CertResult {
	enrichedResultChan := make(chan *CertResult, 1000)
	wg.Add(enrichmentThreads)
	for i := 0; i < enrichmentThreads; i++ {
		go ServerHeaderEnrichmentThread(ctx, rawResultChan, enrichedResultChan, wg)
	}
	return enrichedResultChan
}

func JARMFingerprintEnrichment(ctx context.Context, rawResultChan chan *CertResult, enrichmentThreads int, wg *sync.WaitGroup) chan *CertResult {
	enrichedResultChan := make(chan *CertResult, 1000)
	wg.Add(enrichmentThreads)
	for i := 0; i < enrichmentThreads; i++ {
		go JarmFingerprintEnrichmentThread(ctx, rawResultChan, enrichedResultChan, wg)
	}
	return enrichedResultChan
}

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	log "github.com/sirupsen/logrus"
)

const (
	TOTAL_IPv4_ADDR_COUNT = 3706452992
)

var (
	statsLock         = sync.RWMutex{}
	cidrRangesToScan  = 0
	cidrRangesScanned = 0
	totalIpsScanned   = 0
	totalFindings     = 0

	tcpTimeout = 10
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
	errConn    = fmt.Errorf("could not connect to remote host")
	errNoTls   = fmt.Errorf("could not find TLS on remote port")
	errNoMatch = fmt.Errorf("certificate details did not match requirement")
)

func ScanCertificatesInCidr(ctx context.Context, cidrChan chan string, ports []string, resultChan chan *CertResult, wg *sync.WaitGroup, keywordRegexString string) {
	defer wg.Done()
	keywordRegex := regexp.MustCompile(keywordRegexString)
	for {
		select {
		case <-ctx.Done():
			log.WithFields(log.Fields{"state": "scan"}).Info("context done")
			return
		case cidr, open := <-cidrChan:
			if !open {
				return
			}
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.WithFields(log.Fields{"state": "scan", "errmsg": err.Error(), "cidr": cidr}).Errorf("failed to parse CIDR")
				continue
			}
			log.WithFields(log.Fields{"state": "scan", "cidr": cidr}).Debugf("starting scan for CIDR range")
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				for _, port := range ports {
					remote := getRemoteAddrString(ip.String(), port)
					result, err := ScanRemote(remote, keywordRegex)
					if err != nil {
						log.WithFields(log.Fields{"state": "deepscan", "remote": remote, "errmsg": err.Error()}).Tracef("error")
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

func ScanRemote(remote string, keywordRegex *regexp.Regexp) (*CertResult, error) {
	log.WithFields(log.Fields{"state": "deepscan", "remote": remote}).Tracef("scanning")

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
	log.WithFields(log.Fields{"state": "deepscan", "remote": remote, "subject": certs[0].Subject.String(), "match": subjectMatch || sanMatch}).Debugf("SANs: %s ", certs[0].DNSNames)
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

func SplitCIDR(cidrString string, suffixLenPerGoRoutine int, cidrChan chan string) error {
	cidr := ipaddr.NewIPAddressString(cidrString).GetAddress()
	cidrRange := cidr.GetPrefixLen().Len()
	adjustPrefixLength := 32 - cidrRange - suffixLenPerGoRoutine
	if adjustPrefixLength < 0 {
		adjustPrefixLength = 0
	}
	for i := cidr.AdjustPrefixLen(adjustPrefixLength).PrefixBlockIterator(); i.HasNext(); {
		nextCidr := i.Next().String()
		cidrChan <- nextCidr
		statsLock.Lock()
		cidrRangesToScan += 1
		statsLock.Unlock()
	}
	return nil
}

func main() {
	// input flags
	cspString := flag.String("csp", "", "cloud service provider to search (ex: AWS,GCP)")
	regionString := flag.String("region", ".*", "regex of cloud service provider region to search. (best effort basis)")
	ipCidr := flag.String("cidr", "", "IPv4 CIDR range to search (ex: 192.168.0.1/24)")
	portsString := flag.String("ports", "443", "ports to search (ex: 443,8443)")
	cidrSuffixPerGoRoutine := flag.Int("suffix", 6, "CIDR suffix per goroutine (default 6)")
	debug := flag.Bool("debug", false, "enable debug logs")
	trace := flag.Bool("trace", false, "enable trace logs")
	tcpTimeoutFlag := flag.Int("timeout", 10, "tcp connection timeout in seconds")
	outfileName := flag.String("out", "output.log", "output file on disk")
	threadCount := flag.Int("threads", 2000, "number of parallel threads to use")
	keywordRegexString := flag.String("keyword-regex", ".*", "keyword regex to search in subject or SAN (ex: amazon,google). Default * which matches all")
	flag.Parse()

	// sanity check on input
	if *cspString == "" && *ipCidr == "" {
		log.WithFields(log.Fields{"state": "main"}).Fatal("either -cidr or -csp must be provided")
	}
	if _, err := regexp.Compile(*keywordRegexString); err != nil {
		log.WithFields(log.Fields{"state": "main"}).Fatal("could not compile keyword regex")
	}
	if _, err := regexp.Compile(*regionString); err != nil {
		log.WithFields(log.Fields{"state": "main"}).Fatal("could not compile region regex")
	}
	log.WithFields(log.Fields{"state": "main"}).Info("input passed sanity checks")

	// debug configuration
	if *trace {
		log.SetLevel(log.TraceLevel)
		log.WithFields(log.Fields{"state": "main"}).Info("enabled trace logging")
	} else if *debug {
		log.SetLevel(log.DebugLevel)
		log.WithFields(log.Fields{"state": "main"}).Info("enabled debug logging")
	}

	tcpTimeout = *tcpTimeoutFlag

	log.WithFields(log.Fields{"state": "main"}).Infof("saving output to: %v", *outfileName)
	outFile, err := os.OpenFile(*outfileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.WithFields(log.Fields{"state": "main", "errmsg": err.Error()}).Fatalf("could not open output file for writing")
	}
	defer outFile.Close()

	// variables
	ports := strings.Split(*portsString, ",")
	log.WithFields(log.Fields{"state": "main"}).Infof("parsed ports to scan: %s", ports)
	cidrChan := make(chan string, *threadCount*5)
	resultChan := make(chan *CertResult, *threadCount*2)
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// for CSP scanning
	if *cspString != "" {
		cspCidrChan := make(chan string, *threadCount*2)
		cloudServiceProvider, err := GetCspInstance(*cspString)
		if err != nil {
			log.WithFields(log.Fields{"state": "main"}).Fatal(err)
		}
		go func() {
			cloudServiceProvider.GetCidrRanges(ctx, cspCidrChan, *regionString)
		}()
		go func() {
			defer close(cidrChan)
			for {
				select {
				case <-ctx.Done():
					log.WithFields(log.Fields{"state": "main", "action": "divide-cidr", "csp": *cspString}).Info("context done")
					return
				case cspCidr, open := <-cspCidrChan:
					if !open {
						log.WithFields(log.Fields{"state": "main", "action": "divide-cidr", "csp": *cspString}).Info("done generating sub cidr ranges")
						return
					}
					if err := SplitCIDR(cspCidr, *cidrSuffixPerGoRoutine, cidrChan); err != nil {
						log.WithFields(log.Fields{"state": "main", "action": "divide-cidr", "errmsg": err.Error(), "csp": *cspString}).Fatal("error generating sub-CIDR ranges")
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
				log.WithFields(log.Fields{"state": "main", "action": "divide-cidr", "errmsg": err.Error(), "cidr": *ipCidr}).Fatal("error generating sub-CIDR ranges")
			}
		}()
	}

	// start scanning
	log.WithFields(log.Fields{"state": "main"}).Info("starting scanner threads")
	scanWg := &sync.WaitGroup{}
	scanWg.Add(*threadCount)
	for i := 0; i < *threadCount; i++ {
		go ScanCertificatesInCidr(ctx, cidrChan, ports, resultChan, scanWg, *keywordRegexString)
	}

	// save results to disk
	resultWg := &sync.WaitGroup{}
	resultWg.Add(1)
	go SaveResultsToDisk(resultChan, resultWg, outFile)
	go PrintProgressToConsole(200)

	// wait for everything to finish!
	log.WithFields(log.Fields{"state": "main"}).Info("waiting for threads to finish scanning")
	scanWg.Wait()
	close(resultChan)
	log.WithFields(log.Fields{"state": "main"}).Info("saving results to disk")
	resultWg.Wait()
	log.WithFields(log.Fields{"state": "main"}).Info("done writing results to disk. exiting.")
	Summarize()
}

func Summarize() {
	statsLock.Lock()
	defer statsLock.Unlock()
	percentage := float64(totalIpsScanned) / TOTAL_IPv4_ADDR_COUNT
	fmt.Printf("Total IPs Scanned: %v (%v %% of the public internet)\n", totalIpsScanned, percentage)
	fmt.Printf("Total Findings   : %v \n", totalFindings)
	fmt.Printf("Total CIDR ranges Scanned : %v \n", cidrRangesScanned)
}

func SaveResultsToDisk(resultChan chan *CertResult, resultWg *sync.WaitGroup, outFile *os.File) {
	defer resultWg.Done()
	enc := json.NewEncoder(outFile)
	for result := range resultChan {
		if err := enc.Encode(result); err != nil {
			log.WithFields(log.Fields{"state": "save", "subject": result.Subject, "SANs": fmt.Sprintf("%s", result.SANs)}).Error("error saving result to disk")
		}
		log.WithFields(log.Fields{"state": "save", "subject": result.Subject, "SANs": fmt.Sprintf("%s", result.SANs)}).Debug("")
	}
}

func PrintProgressToConsole(refreshInterval int) {
	for {
		statsLock.RLock()
		fmt.Printf("[ %v / %v ] Findings: %v | TotalIPs: %v |           \r", cidrRangesScanned, cidrRangesToScan, totalFindings, totalIpsScanned)
		statsLock.RUnlock()
		time.Sleep(time.Millisecond * time.Duration(int64(refreshInterval)))
	}
}

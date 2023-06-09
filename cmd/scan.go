package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	logrus "github.com/sirupsen/logrus"
)

func ScanCertificatesInCidr(ctx context.Context, cidrChan chan string, ports []string, resultChan chan *CertResult, wg *sync.WaitGroup, keywordRegexString string) {
	defer wg.Done()
	keywordRegex := regexp.MustCompile("(?i)" + keywordRegexString)
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

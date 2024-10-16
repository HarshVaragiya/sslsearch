package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jedib0t/go-pretty/progress"
	"net"
	"regexp"
	"sync"
	"time"

	logrus "github.com/sirupsen/logrus"
)

func ScanCertificatesInCidr(ctx context.Context, cidrChan chan CidrRange, ports []string, resultChan chan *CertResult, wg *sync.WaitGroup, keywordRegexString string) {
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
			ip, ipNet, err := net.ParseCIDR(cidr.Cidr)
			if err != nil {
				log.WithFields(logrus.Fields{"state": "scan", "errmsg": err.Error(), "cidr": cidr}).Errorf("failed to parse CIDR")
				continue
			}
			log.WithFields(logrus.Fields{"state": "scan", "cidr": cidr}).Debugf("starting scan for CIDR range")
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				for _, port := range ports {
					remote := getRemoteAddrString(ip.String(), port)
					result, err := ScanRemote(ctx, ip, port, keywordRegex)
					if err != nil {
						log.WithFields(logrus.Fields{"state": "deepscan", "remote": remote, "errmsg": err.Error()}).Tracef("error")
						continue
					} else {
						result.CSP = cidr.CSP
						result.Region = cidr.Region
						result.Meta = cidr.Meta
						result.Timestamp = time.Now()
						resultChan <- result
					}
				}
			}
			cidrRangesScanned.Add(1)
		}
	}
}

func ScanRemote(ctx context.Context, ip net.IP, port string, keywordRegex *regexp.Regexp) (*CertResult, error) {
	remote := getRemoteAddrString(ip.String(), port)
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
		ipsScanned.Add(1)
		ipScanRate.Add(1)
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
			totalFindings.Add(1)
			return &CertResult{
				Ip:      ip.String(),
				Port:    port,
				Subject: certs[0].Subject.CommonName,
				Issuer:  certs[0].Issuer.CommonName,
				SANs:    certs[0].DNSNames,
			}, nil
		}
		return nil, errNoMatch
	}
}

func Summarize(start, stop time.Time) {
	elapsedTime := stop.Sub(start)
	percentage := float64(ipsScanned.Load()) / TOTAL_IPv4_ADDR_COUNT
	fmt.Printf("Total IPs Scanned           : %v (%v %% of the internet)\n", ipsScanned.Load(), percentage)
	fmt.Printf("Total Findings              : %v \n", totalFindings.Load())
	fmt.Printf("Total CIDR ranges Scanned   : %v \n", cidrRangesScanned.Load())
	fmt.Printf("Time Elapsed                : %v \n", elapsedTime)
	fmt.Printf("Server Headers              : %v / %v \n", serverHeadersGrabbed.Load(), serverHeadersScanned.Load())
	fmt.Printf("Jarm Fingerprints           : %v / %v \n", jarmFingerprintsGrabbed.Load(), jarmFingerprintsScanned.Load())
	fmt.Printf("Results Export              : %v / %v \n", resultsExported.Load(), resultsProcessed.Load())
	fmt.Printf("Time Elapsed                : %v \n", elapsedTime)
	fmt.Printf("Scan Speed                  : %v IPs/second \n", float64(1000000000*ipsScanned.Load())/float64(elapsedTime))
}

func PrintProgressToConsole(refreshInterval int) {
	for {
		targetsScannedSinceRefresh := ipScanRate.Load()
		ipScanRate.Store(0)
		scanRate := float64(targetsScannedSinceRefresh) / float64(refreshInterval)
		fmt.Printf("Progress: CIDRs [ %v / %v ]  IPs Scanned: %v | Findings: %v | Headers Grabbed: %v / %v | JARM: %v / %v |  Export: %v / %v  | Rate: %.2f  ips/sec         \r",
			cidrRangesScanned.Load(), cidrRangesToScan.Load(),
			ipsScanned.Load(), totalFindings.Load(),
			serverHeadersGrabbed.Load(), serverHeadersScanned.Load(),
			jarmFingerprintsGrabbed.Load(), jarmFingerprintsScanned.Load(),
			resultsExported.Load(), resultsProcessed.Load(), scanRate)
		time.Sleep(time.Second * time.Duration(int64(refreshInterval)))
	}
}

func ProgressBar(refreshInterval int) {
	p := progress.NewWriter()
	defer p.Stop()
	p.SetMessageWidth(24)
	p.SetNumTrackersExpected(4)
	p.SetStyle(progress.StyleDefault)
	p.SetTrackerLength(40)
	p.SetTrackerPosition(progress.PositionRight)
	p.SetUpdateFrequency(time.Second * time.Duration(int64(refreshInterval)))
	p.SetAutoStop(false)
	p.Style().Colors = progress.StyleColorsExample
	go p.Render()
	cidrTracker := progress.Tracker{Message: "CIDR Ranges Scanned"}
	headerTracker := progress.Tracker{Message: "Headers Grabbed"}
	jarmTracker := progress.Tracker{Message: "JARM Fingerprints"}
	exportTracker := progress.Tracker{Message: "Exported Results"}
	log.Printf("starting progress bar thread")
	p.AppendTrackers([]*progress.Tracker{&cidrTracker, &headerTracker, &jarmTracker, &exportTracker})
	for {
		cidrTracker.Total = cidrRangesToScan.Load()
		cidrTracker.SetValue(cidrRangesScanned.Load())
		headerTracker.Total = totalFindings.Load()
		headerTracker.SetValue(serverHeadersScanned.Load())
		jarmTracker.Total = serverHeadersScanned.Load()
		jarmTracker.SetValue(jarmFingerprintsScanned.Load())
		exportTracker.Total = jarmFingerprintsScanned.Load()
		exportTracker.SetValue(resultsExported.Load())
		if exportTracker.IsDone() && state < 4 {
			// progress bar does not update number after it is marked "done" so keep it "undone" till we wait for export to finish
			exportTracker.SetValue(exportTracker.Total - 1)
		}
		time.Sleep(time.Second)
	}
}

func ServerHeaderEnrichment(ctx context.Context, rawResultChan chan *CertResult, enrichmentThreads int, wg *sync.WaitGroup) chan *CertResult {
	enrichedResultChan := make(chan *CertResult, enrichmentThreads*2000)
	wg.Add(enrichmentThreads)
	for i := 0; i < enrichmentThreads; i++ {
		go headerEnrichmentThread(ctx, rawResultChan, enrichedResultChan, wg)
	}
	return enrichedResultChan
}

func JARMFingerprintEnrichment(ctx context.Context, rawResultChan chan *CertResult, enrichmentThreads int, wg *sync.WaitGroup) chan *CertResult {
	enrichedResultChan := make(chan *CertResult, enrichmentThreads*2000)
	wg.Add(enrichmentThreads)
	for i := 0; i < enrichmentThreads; i++ {
		go jarmFingerprintEnrichmentThread(ctx, rawResultChan, enrichedResultChan, wg)
	}
	return enrichedResultChan
}

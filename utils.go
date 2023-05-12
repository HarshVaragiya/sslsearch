package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var (
	httpClientPool = sync.Pool{
		New: func() interface{} {
			return &fasthttp.Client{
				TLSConfig: &tls.Config{
					InsecureSkipVerify: true,
					// for server header check skip SSL validation
				},
			}
		},
	}
)

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

func SplitCIDR(cidrString string, suffixLenPerGoRoutine int, cidrChan chan string) error {
	cidr := ipaddr.NewIPAddressString(cidrString).GetAddress()
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
		cidrChan <- nextCidr
	}
	return nil
}

func ServerHeaderEnrichmentThread(rawResultChan, enrichedResultChan chan *CertResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for rawResult := range rawResultChan {
		if header, err := GrabServerHeaderForRemote(rawResult.RemoteAddr); err == nil {
			rawResult.ServerHeader = header
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": rawResult.RemoteAddr}).Debugf("server: %v", header)
		} else {
			log.WithFields(logrus.Fields{"state": "enrichment", "remote": rawResult.RemoteAddr, "errmsg": err.Error()}).Tracef("server: %v ", header)
		}
		enrichedResultChan <- rawResult
	}
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

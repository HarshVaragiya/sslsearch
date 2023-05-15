package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/HarshVaragiya/jarm-go"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
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
	return res.Hash, err
}

func SplitRemoteAddr(remote string) (host string, port int) {
	s := strings.Split(remote, ":")
	host = s[0]
	port, _ = strconv.Atoi(s[1])
	return
}

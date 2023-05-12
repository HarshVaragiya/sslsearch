package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"

	logrus "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type GCP struct {
}

type GcpPrefix struct {
	Ipv4Prefix string `json:"ipv4Prefix"` // IPv4 Cidr that usually appears
	Ipv6Prefix string `json:"ipv6Prefix"` // Ipv6 Cidr that appears sometimes
	// Service    string `json:"service"` # always remains "Google Cloud" hence skipped
	Scope string `json:"scope"` // Region Key
}

type GcpIPRangeResponse struct {
	SyncToken    string       `json:"syncToken"`
	CreationTime string       `json:"creationTime"`
	Prefixes     []*GcpPrefix `json:"prefixes"`
}

func (gcp GCP) GetCidrRanges(ctx context.Context, cidrChan chan string, region string) {
	var ipRangesResponse GcpIPRangeResponse

	defer close(cidrChan)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(GOOGLE_CLOUD_IP_RANGES_URL)

	log.WithFields(logrus.Fields{"state": "GCP", "action": "get-cidr-range"}).Info("fetching IP ranges")
	err := fasthttp.Do(req, resp)

	regionRegex := regexp.MustCompile(region)

	if err != nil {
		log.WithFields(logrus.Fields{"state": "GCP", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error fetching IP ranges")
	}
	respBody := resp.Body()
	dec := json.NewDecoder(bytes.NewReader(respBody))
	for dec.More() {
		if err := dec.Decode(&ipRangesResponse); err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(logrus.Fields{"state": "GCP", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error parsing response")
		}
		for _, prefix := range ipRangesResponse.Prefixes {
			select {
			case <-ctx.Done():
				log.WithFields(logrus.Fields{"state": "GCP", "action": "get-cidr-range"}).Info("recieved context cancellation")
				return
			default:
				if regionRegex.MatchString(prefix.Scope) {
					if prefix.Ipv6Prefix != "" {
						continue
					}
					cidrChan <- prefix.Ipv4Prefix
					log.WithFields(logrus.Fields{"state": "GCP", "action": "get-cidr-range"}).Debugf("added %v to scan target", prefix.Ipv4Prefix)
				}
			}
		}
	}
	log.WithFields(logrus.Fields{"state": "GCP", "action": "get-cidr-range"}).Info("done adding all IPs")
}

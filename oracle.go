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

type Oracle struct {
}

type OracleRegionCidr struct {
	Cidr string `json:"cidr"`
}
type RegionsElement struct {
	Region            string              `json:"region"`
	OracleRegionCidrs []*OracleRegionCidr `json:"cidrs"`
}

type OracleIPRangeResponse struct {
	RegionsElements []*RegionsElement `json:"regions"`
}

func (oracle Oracle) GetCidrRanges(ctx context.Context, cidrChan chan string, region string) {
	var ipRangesResponse OracleIPRangeResponse

	defer close(cidrChan)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(ORACLE_CLOUD_IP_RANGES_URL)

	log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range"}).Info("fetching IP ranges")
	err := fasthttp.Do(req, resp)

	regionRegex := regexp.MustCompile(region)

	if err != nil {
		log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error fetching IP ranges")
	}
	respBody := resp.Body()
	dec := json.NewDecoder(bytes.NewReader(respBody))
	for dec.More() {
		if err := dec.Decode(&ipRangesResponse); err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error parsing response")
		}
		for _, regionElement := range ipRangesResponse.RegionsElements {
			if regionRegex.MatchString(regionElement.Region) {
				for _, cidr := range regionElement.OracleRegionCidrs {
					select {
					case <-ctx.Done():
						log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range"}).Info("recieved context cancellation")
						return
					default:
						cidrChan <- cidr.Cidr
						log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range"}).Debugf("added %v to scan target", cidr.Cidr)
					}
				}
			}
		}
	}
	log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range"}).Info("done adding all IPs")
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"

	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type AWS struct {
}

type AwsIPRangeResponse struct {
	SyncToken  string       `json:"syncToken"`
	CreateDate string       `json:"createDate"`
	Prefixes   []*AwsPrefix `json:"prefixes"`
}

type AwsPrefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
	// NetworkBorderGroup string `json:"network_border_group"` IGNORED
}

func (aws AWS) GetCidrRanges(ctx context.Context, cidrChan chan string, region string) {
	var ipRangesResponse AwsIPRangeResponse

	defer close(cidrChan)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(AWS_IP_RANGES_URL)

	log.WithFields(log.Fields{"state": "AWS", "action": "get-cidr-range"}).Info("fetching IP ranges from AWS")
	err := fasthttp.Do(req, resp)

	regionRegex := regexp.MustCompile(region)

	if err != nil {
		log.WithFields(log.Fields{"state": "AWS", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error fetching IP ranges from AWS")
	}
	respBody := resp.Body()
	dec := json.NewDecoder(bytes.NewReader(respBody))
	for dec.More() {
		if err := dec.Decode(&ipRangesResponse); err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(log.Fields{"state": "AWS", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error parsing response")
		}
		for _, prefix := range ipRangesResponse.Prefixes {
			select {
			case <-ctx.Done():
				log.WithFields(log.Fields{"state": "AWS", "action": "get-cidr-range"}).Info("recieved context cancellation")
				return
			default:
				if regionRegex.MatchString(prefix.Region) {
					cidrChan <- prefix.IPPrefix
					log.WithFields(log.Fields{"state": "AWS", "action": "get-cidr-range"}).Debugf("added %v to scan target", prefix.IPPrefix)
				}
			}
		}
	}
	log.WithFields(log.Fields{"state": "AWS", "action": "get-cidr-range"}).Info("done adding all IPs from AWS to scan target")
}

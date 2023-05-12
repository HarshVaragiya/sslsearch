package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"regexp"
	"strings"

	logrus "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type DigitalOcean struct {
}

func (digitalOcean DigitalOcean) GetCidrRanges(ctx context.Context, cidrChan chan string, region string) {
	defer close(cidrChan)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(DIGITALOCEAN_IP_RANGES_URL)

	log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range"}).Info("fetching IP ranges")
	err := fasthttp.Do(req, resp)

	regionRegex := regexp.MustCompile(region)

	if err != nil {
		log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error fetching IP ranges")
	}
	respBody := resp.Body()
	reader := csv.NewReader(bytes.NewReader(respBody))
	done := false
	for !done {
		select {
		case <-ctx.Done():
			log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range"}).Info("recieved context cancellation")
			done = true
			return
		default:
			record, err := reader.Read()
			if err != nil && err != io.EOF {
				log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error parsing response")
				done = true
				break
			} else if err == io.EOF {
				done = true
				break
			}
			cidr := record[0]
			regionNameString := strings.Join(record[1:4], "_")
			if regionRegex.MatchString(regionNameString) {
				cidrChan <- cidr
				log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range"}).Debugf("added %v to scan target", cidr)
			}
		}
	}
	log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range"}).Info("done adding all IPs")
}

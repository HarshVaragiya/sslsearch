package main

import (
	"context"
	"strings"

	logrus "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type Cloudflare struct {
}

func (cloudflare Cloudflare) GetCidrRanges(ctx context.Context, cidrChan chan string, region string) {
	defer close(cidrChan)

	log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range"}).Warning("region filtering not supported!")

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(CLOUDFLARE_IPv4_RANGES_URL)

	log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range"}).Info("fetching IP ranges")
	err := fasthttp.Do(req, resp)

	if err != nil {
		log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error fetching IP ranges")
	}
	respBody := resp.Body()

	cidrs := strings.Split(string(respBody), "\n")
	for _, cidr := range cidrs {
		select {
		case <-ctx.Done():
			log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range"}).Info("recieved context cancellation")
			return
		default:
			cidrChan <- cidr
			log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range"}).Debugf("added %v to scan target", cidr)
		}
	}
	log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range"}).Info("done adding all IPs")
}

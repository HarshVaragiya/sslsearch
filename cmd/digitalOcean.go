/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

// digitalOceanCmd represents the digitalOcean command
var digitalOceanCmd = &cobra.Command{
	Use:   "digitalOcean",
	Short: "Scan for a target on Digital Ocean. Region filtering supported",
	Run: func(cmd *cobra.Command, args []string) {

		PerformPreRunChecks(true)
		ScanCloudServiceProvider(context.TODO(), "DigitalOcean", DigitalOcean{})

	},
}

func init() {
	rootCmd.AddCommand(digitalOceanCmd)
	digitalOceanCmd.Flags().StringVarP(&regionRegexString, "region-regex", "r", ".*", "regex of cloud service provider region to search")
}

type DigitalOcean struct {
}

func (digitalOcean DigitalOcean) GetCidrRanges(ctx context.Context, cidrChan chan CidrRange, region string) {
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
				log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range", "errmsg": err.Error()}).Errorf("error parsing response")
				continue
			} else if err == io.EOF {
				done = true
				break
			}
			cidr := record[0]
			// skip IPv6 addresses
			if strings.Contains(cidr, "::") {
				continue
			}
			regionNameString := strings.Join(record[1:4], "_")
			if regionRegex.MatchString(regionNameString) {
				cidrChan <- CidrRange{Cidr: cidr, CSP: "DigitalOcean", Region: regionNameString}
				log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range"}).Debugf("added %v to scan target for region %v", cidr, regionNameString)
			} else {
				log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range"}).Debugf("skipped %v from region %v", cidr, regionNameString)
			}
		}
	}
	log.WithFields(logrus.Fields{"state": "DigitalOcean", "action": "get-cidr-range"}).Info("done adding all IPs")
}

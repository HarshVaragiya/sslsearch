/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

// ociCmd represents the oci command
var ociCmd = &cobra.Command{
	Use:   "oci",
	Short: "Scan for a target on Oracle Cloud Infrastructure. Region filtering supported",
	Run: func(cmd *cobra.Command, args []string) {

		PerformPreRunChecks(true)
		ScanCloudServiceProvider(context.TODO(), "OCI", Oracle{})

	},
}

func init() {
	rootCmd.AddCommand(ociCmd)
	ociCmd.Flags().StringVarP(&regionRegexString, "region-regex", "r", ".*", "regex of cloud service provider region to search")
}

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

func (oracle Oracle) GetCidrRanges(ctx context.Context, cidrChan chan CidrRange, region string) {
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
						cidrChan <- CidrRange{Cidr: cidr.Cidr, CSP: "OCI", Region: regionElement.Region}
						log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range"}).Debugf("added %v to scan target", cidr.Cidr)
					}
				}
			} else {
				log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range"}).Debugf("skipped region %v", regionElement.Region)
			}
		}
	}
	log.WithFields(logrus.Fields{"state": "OCI", "action": "get-cidr-range"}).Info("done adding all IPs")
}

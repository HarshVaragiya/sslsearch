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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// ociCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// ociCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
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

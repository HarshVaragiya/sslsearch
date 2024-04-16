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

// awsCmd represents the aws command
var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Scan for a target on Amazon Web Services. Region filtering supported",
	Run: func(cmd *cobra.Command, args []string) {

		PerformPreRunChecks(true)
		ScanCloudServiceProvider(context.TODO(), "AWS", AWS{})

	},
}

func init() {
	rootCmd.AddCommand(awsCmd)
	awsCmd.Flags().StringVarP(&regionRegexString, "region-regex", "r", ".*", "regex of cloud service provider region to search")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// awsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// awsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

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

func (aws AWS) GetCidrRanges(ctx context.Context, cidrChan chan CidrRange, region string) {
	var ipRangesResponse AwsIPRangeResponse

	defer close(cidrChan)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(AWS_IP_RANGES_URL)

	log.WithFields(logrus.Fields{"state": "AWS", "action": "get-cidr-range"}).Info("fetching IP ranges from AWS")
	err := fasthttp.Do(req, resp)

	regionRegex := regexp.MustCompile(region)

	if err != nil {
		log.WithFields(logrus.Fields{"state": "AWS", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error fetching IP ranges from AWS")
	}
	respBody := resp.Body()
	dec := json.NewDecoder(bytes.NewReader(respBody))
	for dec.More() {
		if err := dec.Decode(&ipRangesResponse); err != nil {
			if err == io.EOF {
				break
			}
			log.WithFields(logrus.Fields{"state": "AWS", "action": "get-cidr-range", "errmsg": err.Error()}).Fatal("error parsing response")
		}
		for _, prefix := range ipRangesResponse.Prefixes {
			select {
			case <-ctx.Done():
				log.WithFields(logrus.Fields{"state": "AWS", "action": "get-cidr-range"}).Info("recieved context cancellation")
				return
			default:
				if regionRegex.MatchString(prefix.Region) {
					cidrChan <- CidrRange{Cidr: prefix.IPPrefix, CSP: "AWS", Region: prefix.Region, Meta: prefix.Service}
					log.WithFields(logrus.Fields{"state": "AWS", "action": "get-cidr-range"}).Debugf("added %v to scan target for region %v", prefix.IPPrefix, prefix.Region)
				} else {
					log.WithFields(logrus.Fields{"state": "AWS", "action": "get-cidr-range"}).Debugf("skipped %v from region %v", prefix.IPPrefix, prefix.Region)
				}
			}
		}
	}
	log.WithFields(logrus.Fields{"state": "AWS", "action": "get-cidr-range"}).Info("done adding all IPs from AWS to scan target")
}

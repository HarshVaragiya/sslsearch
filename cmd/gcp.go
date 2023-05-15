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

// gcpCmd represents the gcp command
var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Scan for a target on Google Cloud Platform. Region filtering supported",
	Run: func(cmd *cobra.Command, args []string) {

		PerformPreRunChecks(true)
		ScanCloudServiceProvider(context.TODO(), "GCP", GCP{})

	},
}

func init() {
	rootCmd.AddCommand(gcpCmd)
	gcpCmd.Flags().StringVarP(&regionRegexString, "region-regex", "r", ".*", "regex of cloud service provider region to search")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// gcpCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// gcpCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

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

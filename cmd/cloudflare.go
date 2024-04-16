/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

// cloudflareCmd represents the cloudflare command
var cloudflareCmd = &cobra.Command{
	Use:   "cloudflare",
	Short: "Scan for a target on CloudFlare. Region filtering is not supported",
	Run: func(cmd *cobra.Command, args []string) {

		PerformPreRunChecks(false)
		ScanCloudServiceProvider(context.TODO(), "CloudFlare", Cloudflare{})

	},
}

func init() {
	rootCmd.AddCommand(cloudflareCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// cloudflareCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cloudflareCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

type Cloudflare struct {
}

func (cloudflare Cloudflare) GetCidrRanges(ctx context.Context, cidrChan chan CidrRange, region string) {
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
			cidrChan <- CidrRange{Cidr: cidr, CSP: "Cloudflare", Region: "Unknown"}
			log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range"}).Debugf("added %v to scan target", cidr)
		}
	}
	log.WithFields(logrus.Fields{"state": "Cloudflare", "action": "get-cidr-range"}).Info("done adding all IPs")
}

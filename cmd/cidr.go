/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// cidrCmd represents the cidr command
var cidrCmd = &cobra.Command{
	Use:   "cidr",
	Short: "Scan SSL certificates for a given CIDR range",
	Run: func(cmd *cobra.Command, args []string) {

		PerformPreRunChecks(false)

		// sanity check
		if len(args) != 1 {
			log.WithFields(logrus.Fields{"state": "main"}).Fatalf("error parsing input args as CIDR. args: %v", args)
		}

		cidrChan := make(chan CidrRange, threadCount*5)
		// generate input ips
		go func() {
			defer close(cidrChan)
			cidr := CidrRange{Cidr: args[0], CSP: "NA", Region: "NA"}
			err := SplitCIDR(cidr, cidrSuffixPerGoRoutine, cidrChan)
			if err != nil {
				log.WithFields(logrus.Fields{"state": "main", "action": "divide-cidr", "errmsg": err.Error(), "cidr": args[0]}).Fatal("error generating sub-CIDR ranges")
			}
		}()

		// process input
		RunScan(cidrChan)
	},
}

func init() {
	rootCmd.AddCommand(cidrCmd)
}

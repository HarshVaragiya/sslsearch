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

		cidrChan := make(chan string, threadCount*5)
		// generate input ips
		go func() {
			defer close(cidrChan)
			err := SplitCIDR(args[0], cidrSuffixPerGoRoutine, cidrChan)
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// cidrCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cidrCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

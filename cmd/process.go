/*
Copyright © 2024 Harsh Varagiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	workerThreadCount         = 1024
	workerScannerPorts        = []string{"443"}
	workerServerHeaderThreads = 8
	workerJarmThreads         = 32
)

// processCmd represents the process command
var processCmd = &cobra.Command{
	Use:   "process",
	Short: "process background jobs from queue for scanning",
	Run: func(cmd *cobra.Command, args []string) {
		UpdateLogLevel()
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			s := <-signals
			log.WithFields(logrus.Fields{"state": "main"}).Infof("received %v ... cancelling context.", s.String())
			cancelFunc()
			s = <-signals
			log.WithFields(logrus.Fields{"state": "main"}).Fatalf("forcing exit due to %v", s.String())
			os.Exit(-1)
		}()

		rdb := redis.NewClient(&redis.Options{
			Addr:     redisHost,
			Password: "", // no password set
			DB:       0,  // use default DB
		})

		PerformOutputChecks()
		for {
			exportTarget := GetExportTarget()
			initialResultChan := make(chan *CertResult, 1024)
			log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "namespace": taskQueue}).Info("getting next task from queue")
			data, err := rdb.LPop(ctx, taskQueue).Bytes()
			if err != nil {
				log.WithFields(logrus.Fields{"state": "process", "errmsg": err, "type": "mgmt"}).Error("error popping task from queue")
				time.Sleep(time.Second * 30)
				continue
			}
			go PrintProgressToConsole(consoleRefreshSeconds)
			var cidrRange CidrRange
			if err = json.Unmarshal(data, &cidrRange); err != nil {
				log.WithFields(logrus.Fields{"state": "process", "errmsg": err, "type": "mgmt"}).Error("error parsing task")
			}
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Infof("processing task")

			scanWg := &sync.WaitGroup{}
			scanWg.Add(workerThreadCount)
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Debugf("starting cidr-split task")
			processCidrRange := make(chan CidrRange, 1024)
			go func() {
				SplitCIDR(cidrRange, cidrSuffixPerGoRoutine, processCidrRange)
				close(processCidrRange)
			}()
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Debugf("starting tls scanning threads")
			for i := 0; i < workerThreadCount; i++ {
				go ScanCertificatesInCidr(ctx, processCidrRange, workerScannerPorts, initialResultChan, scanWg, ".*")
			}
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Debugf("starting header grabbing threads")
			serverHeaderWg := &sync.WaitGroup{}
			headerEnrichedResultsChan := ServerHeaderEnrichment(ctx, initialResultChan, workerServerHeaderThreads, serverHeaderWg)
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Debugf("starting jarm fingerprinting")
			jarmFingerprintWg := &sync.WaitGroup{}
			enrichedResultChan := JARMFingerprintEnrichment(ctx, headerEnrichedResultsChan, workerJarmThreads, jarmFingerprintWg)
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Debugf("starting export thread")
			resultWg := &sync.WaitGroup{}
			resultWg.Add(1)
			go exportTarget.Export(enrichedResultChan, resultWg)
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Infof("started all processing threads")
			scanWg.Wait()
			close(initialResultChan)
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Infof("tls scanning finished")
			serverHeaderWg.Wait()
			close(headerEnrichedResultsChan)
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Infof("server header grabbing finished")
			jarmFingerprintWg.Wait()
			close(enrichedResultChan)
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Infof("jarm fingerprinting finished")
			resultWg.Wait()
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Infof("result exporting finished")
		}
	},
}

func init() {
	workerCmd.AddCommand(processCmd)
}

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
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	workerThreadCount         = 4096
	workerScannerPorts        = []string{"443"}
	workerServerHeaderThreads = 48
	workerJarmThreads         = 128
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
		go func() {
			endpoint := os.Getenv("MINIO_ENDPOINT")
			accessKey := os.Getenv("ACCESS_KEY")
			secretKey := os.Getenv("SECRET_KEY")
			hostname, _ := os.Hostname()
			minioClient, err := minio.New(endpoint, &minio.Options{
				Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
				Secure: false,
			})
			if err != nil {
				log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error connecting to MinIO server")
			}
			for {
				time.Sleep(time.Minute)
				val, err := rdb.Get(ctx, "profile").Int()
				if err != nil {
					log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Debugf("error getting profile control variable")
				}
				if val == 1 {
					log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt"}).Infof("attempting to profile application")
					tmpFileName := "/tmp/" + uuid.NewString() + ".prof"
					tmpFile, err := os.Create(tmpFileName)
					if err != nil {
						log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error creating tmp file for profiling")
						continue
					}
					err = pprof.StartCPUProfile(tmpFile)
					if err != nil {
						log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error starting profiling")
						continue
					}
					time.Sleep(time.Minute)
					pprof.StopCPUProfile()
					tmpFile.Close()
					objectName := fmt.Sprintf("profiles/%s-%s.prof", hostname, time.Now().Format("2006-01-02-15-04-05"))
					info, err := minioClient.FPutObject(ctx, "projects-sslsearch", objectName, tmpFileName, minio.PutObjectOptions{ContentType: "application/octet-stream"})
					if err != nil {
						log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error uploading profile to minio server")
						continue
					}
					log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt"}).Infof("uploaded profile '%s' of size %d bytes", info.Key, info.Size)
				}
			}
		}()

		exportTarget := GetExportTarget()
		initialResultChan := make(chan *CertResult, workerThreadCount*32)
		scanWg := &sync.WaitGroup{}
		scanWg.Add(workerThreadCount)
		processCidrRange := make(chan CidrRange, workerThreadCount*2)
		log.WithFields(logrus.Fields{"state": "process"}).Debugf("starting tls scanning threads")
		for i := 0; i < workerThreadCount; i++ {
			go ScanCertificatesInCidr(ctx, processCidrRange, workerScannerPorts, initialResultChan, scanWg, ".*")
		}
		log.WithFields(logrus.Fields{"state": "process"}).Debugf("starting header grabbing threads")
		serverHeaderWg := &sync.WaitGroup{}
		headerEnrichedResultsChan := ServerHeaderEnrichment(ctx, initialResultChan, workerServerHeaderThreads, serverHeaderWg)
		log.WithFields(logrus.Fields{"state": "process"}).Debugf("starting jarm fingerprinting")
		jarmFingerprintWg := &sync.WaitGroup{}
		enrichedResultChan := JARMFingerprintEnrichment(ctx, headerEnrichedResultsChan, workerJarmThreads, jarmFingerprintWg)
		log.WithFields(logrus.Fields{"state": "process"}).Debugf("starting export thread")
		resultWg := &sync.WaitGroup{}
		resultWg.Add(1)
		go exportTarget.Export(enrichedResultChan, resultWg)
		log.WithFields(logrus.Fields{"state": "process"}).Info("started all processing threads")

	WorkerLoop:
		for {
			log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "namespace": taskQueue}).Debugf("getting next task from queue")
			select {
			case <-ctx.Done():
				log.WithFields(logrus.Fields{"state": "process", "type": "mgmt"}).Infof("context done. exiting worker loop")
				break WorkerLoop
			default:
				break
			}
			data, err := rdb.LPop(ctx, taskQueue).Bytes()
			if err != nil {
				log.WithFields(logrus.Fields{"state": "process", "errmsg": err, "type": "mgmt"}).Errorf("error popping task from queue")
				time.Sleep(time.Second * 30)
				continue
			}
			// go PrintProgressToConsole(consoleRefreshSeconds)
			var cidrRange CidrRange
			if err = json.Unmarshal(data, &cidrRange); err != nil {
				log.WithFields(logrus.Fields{"state": "process", "errmsg": err, "type": "mgmt"}).Error("error parsing task")
			}
			log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr}).Infof("processing task")
			SplitCIDR(cidrRange, cidrSuffixPerGoRoutine, processCidrRange)

		}
		log.WithFields(logrus.Fields{"state": "process", "type": "mgmt"}).Infof("waiting for scanner threads to finish!")
		scanWg.Wait()
		close(initialResultChan)
		log.WithFields(logrus.Fields{"state": "process"}).Info("tls scanning finished")
		serverHeaderWg.Wait()
		close(headerEnrichedResultsChan)
		log.WithFields(logrus.Fields{"state": "process"}).Info("server header grabbing finished")
		jarmFingerprintWg.Wait()
		close(enrichedResultChan)
		log.WithFields(logrus.Fields{"state": "process"}).Info("jarm fingerprinting finished")
		resultWg.Wait()
		log.WithFields(logrus.Fields{"state": "process"}).Infof("result exporting finished")
	},
}

func init() {
	workerCmd.AddCommand(processCmd)
}

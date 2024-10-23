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
	"errors"
	"fmt"
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

		if redisHost == "" {
			redisHost = os.Getenv("REDIS_HOST")
			if redisHost == "" {
				log.Fatalf("missing required parameter for redis host")
			}
		}

		UpdateLogLevel()
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

		// we read job from the in-progress queue and only if that is empty, we read from todo queue
		go func() {
			for {
				s := <-signals
				log.WithFields(logrus.Fields{"state": "main"}).Infof("received %v ... cancelling context.", s.String())
				cancelFunc()
				log.WithFields(logrus.Fields{"state": "main"}).Infof("waiting for threads to finish ...")
			}
		}()

		rdb := redis.NewClient(&redis.Options{
			Addr:     redisHost,
			Password: "", // no password set
			DB:       0,  // use default DB
		})

		for {
			job, err := GetJobToBeDone(ctx, rdb)
			if err != nil {
				log.WithFields(logrus.Fields{"state": "process.config", "errmsg": err}).Fatalf("error getting job from redis")
				time.Sleep(time.Minute * 5)
				continue
			}
			exportTarget, err := NewElasticsearch(elasticsearchHost, elasticsearchUsername, elasticsearchPassword, job.ExportIndex)
			if err != nil {
				log.WithFields(logrus.Fields{"state": "process.config", "errmsg": err}).Fatalf("error configuring elasticsearch export target")
			}
			initialResultChan := make(chan *CertResult, workerThreadCount*32)
			scanWg := &sync.WaitGroup{}
			scanWg.Add(workerThreadCount)
			processCidrRange := make(chan CidrRange, workerThreadCount*2)
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Debugf("starting tls scanning threads")
			for i := 0; i < workerThreadCount; i++ {
				go ScanCertificatesInCidr(ctx, processCidrRange, workerScannerPorts, initialResultChan, scanWg, ".*")
			}
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Debugf("starting header grabbing threads")
			serverHeaderWg := &sync.WaitGroup{}
			headerEnrichedResultsChan := ServerHeaderEnrichment(ctx, initialResultChan, workerServerHeaderThreads, serverHeaderWg)
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Debugf("starting jarm fingerprinting")
			jarmFingerprintWg := &sync.WaitGroup{}
			enrichedResultChan := JARMFingerprintEnrichment(ctx, headerEnrichedResultsChan, workerJarmThreads, jarmFingerprintWg)
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Debugf("starting export thread")
			resultWg := &sync.WaitGroup{}
			resultWg.Add(1)
			go exportTarget.Export(enrichedResultChan, resultWg)
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Info("started all processing threads")

			hostname, _ := os.Hostname()
			statsPrefix := fmt.Sprintf("sslsearch:workers:%s", hostname)
			profilePrefix := fmt.Sprintf("runtime-profiles/%s", hostname)
			go ProfileRuntime(ctx, rdb, profilePrefix)
			go ExportStatsPeriodically(ctx, rdb, job, statsPrefix, time.Duration(consoleRefreshSeconds)*time.Second)
			go PrintProgressToConsole(consoleRefreshSeconds)

		WorkerLoop:
			for {
				log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "job-id": job.JobId}).Debugf("getting next task from queue")
				select {
				case <-ctx.Done():
					log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "job-id": job.JobId}).Infof("context done. exiting worker loop")
					close(processCidrRange)
					break WorkerLoop
				default:
					break
				}
				data, err := rdb.LPop(ctx, job.TaskQueue).Bytes()
				if err != nil {
					if errors.Is(err, redis.Nil) {
						log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "job-id": job.JobId}).Infof("task queue empty. trying to move it to done")
						jobString, _ := json.Marshal(job)
						count, err := rdb.LRem(ctx, SSLSEARCH_JOBS_IN_PROGRESS, 0, jobString).Result()
						if err != nil {
							log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "job-id": job.JobId, "errmsg": err}).Errorf("error deleting task from in-progress queue")
						} else if count == 1 {
							err := rdb.LPush(ctx, SSLSEARCH_JOB_QUEUE_DONE, jobString).Err()
							if err != nil {
								log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "job-id": job.JobId, "errmsg": err}).Errorf("error adding task to done queue")
							}
							log.WithFields(logrus.Fields{"state": "process", "type": "mgmt", "job-id": job.JobId}).Infof("added job to done queue")
						}
						close(processCidrRange)
						break WorkerLoop
					}
					log.WithFields(logrus.Fields{"state": "process", "errmsg": err, "type": "mgmt", "job-id": job.JobId}).Errorf("error popping task from queue")
					time.Sleep(time.Minute)
					continue
				}
				var cidrRange CidrRange
				if err = json.Unmarshal(data, &cidrRange); err != nil {
					log.WithFields(logrus.Fields{"state": "process", "errmsg": err, "type": "mgmt", "job-id": job.JobId}).Error("error parsing task")
				}
				log.WithFields(logrus.Fields{"state": "process", "csp": cidrRange.CSP, "region": cidrRange.Region, "cidr": cidrRange.Cidr, "job-id": job.JobId}).Infof("processing task")
				SplitCIDR(cidrRange, cidrSuffixPerGoRoutine, processCidrRange)
			}
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Infof("waiting for scanner threads to finish!")
			scanWg.Wait()
			close(initialResultChan)
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Info("tls scanning finished")
			serverHeaderWg.Wait()
			close(headerEnrichedResultsChan)
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Info("server header grabbing finished")
			jarmFingerprintWg.Wait()
			close(enrichedResultChan)
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Info("jarm fingerprinting finished")
			resultWg.Wait()
			log.WithFields(logrus.Fields{"state": "process", "job-id": job.JobId}).Infof("result exporting finished")
		}
	},
}

func init() {
	workerCmd.AddCommand(processCmd)
}

func GetJobToBeDone(ctx context.Context, rdb *redis.Client) (*Job, error) {
	var job Job
	jobsInProgress, err := rdb.LRange(ctx, SSLSEARCH_JOBS_IN_PROGRESS, 0, 1).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		log.WithFields(logrus.Fields{"state": "process.config", "errmsg": err}).Errorf("error getting elements from in-progress job queue")
		return &job, err
	}
	if err == nil && len(jobsInProgress) >= 1 {
		jobJson := jobsInProgress[0]
		err := json.Unmarshal([]byte(jobJson), &job)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "process.config", "errmsg": err}).Errorf("error unmarshalling job into JSON")
			return &job, err
		}
		log.WithFields(logrus.Fields{"state": "process.config"}).Infof("job found: %s", job.Name)
		return &job, nil
	}
	jobJson, err := rdb.RPopLPush(ctx, SSLSEARCH_JOB_QUEUE_TODO, SSLSEARCH_JOBS_IN_PROGRESS).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		log.WithFields(logrus.Fields{"state": "process.config", "errmsg": err}).Errorf("error getting elements from todo job queue")
		return &job, err
	}
	if err == nil {
		if err := json.Unmarshal([]byte(jobJson), &job); err != nil {
			log.WithFields(logrus.Fields{"state": "process.config", "errmsg": err}).Errorf("error unmarshalling job into JSON")
			return &job, err
		}
		log.WithFields(logrus.Fields{"state": "process.config"}).Infof("job found: %s", job.Name)
		return &job, nil
	}
	log.WithFields(logrus.Fields{"state": "process.config"}).Infof("no jobs found in the queue to be done")
	return nil, fmt.Errorf("no job found in queue")
}

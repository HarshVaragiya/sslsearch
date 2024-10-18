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
	"github.com/google/uuid"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
)

var (
	jobName        string
	jobDescription string
	jobExportIndex string
	targetCsps     string
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add jobs to worker queue",
	Run: func(cmd *cobra.Command, args []string) {

		if redisHost == "" {
			redisHost = os.Getenv("REDIS_HOST")
			if redisHost == "" {
				log.Fatalf("missing required parameter for redis host")
			}
		}

		rdb := redis.NewClient(&redis.Options{
			Addr:     redisHost,
			Password: "", // no password set
			DB:       0,  // use default DB
		})

		if jobName == "" {
			jobName = fmt.Sprintf("sslsearch-%s", time.Now().Format("2006-01-02"))
		}
		if jobDescription == "" {
			desc := strings.Builder{}
			desc.WriteString(fmt.Sprintf("Job Description: %s \n", jobName))
			desc.WriteString(fmt.Sprintf("Trigger: probably cron\n"))
			jobDescription = desc.String()
		}
		if jobExportIndex == "" {
			jobExportIndex = jobName
		}

		jobId := uuid.New().String()
		jobTaskQueue := fmt.Sprintf("sslsearch:task-queue:%s", jobId)
		log.Printf("creating job: %s with id: %s", jobName, jobId)

		CheckRegionRegex()

		job := &Job{
			JobId:         jobId,
			TaskQueue:     jobTaskQueue,
			Name:          jobName,
			Description:   jobDescription,
			ExportIndex:   jobExportIndex,
			Status:        "todo",
			JobSubmitTime: time.Now(),
		}

		cspStrings := strings.Split(targetCsps, ",")
		cidrs := make(chan CidrRange, 32)
		subCidrs := make(chan CidrRange, 32)
		ctx := context.Background()

		go func() {
			for parentCidr := range cidrs {
				// log.Printf("splitting CIDR %v into sub-cidr ranges", parentCidr.Cidr)
				SplitCIDR(parentCidr, cidrSuffixPerGoRoutine, subCidrs)
			}
			close(subCidrs)
		}()

		go func() {
			wg := &sync.WaitGroup{}
			for _, cspString := range cspStrings {
				log.Printf("attempting to add sub-cidr ranges for %s to job queue", cspString)
				cspInstance, err := GetCspInstance(cspString)
				if err != nil {
					log.Fatalf("error getting CSP instance for %s", cspString)
				}
				cspCidrs := make(chan CidrRange, 32)
				wg.Add(1)
				go func() {
					defer wg.Done()
					for cidr := range cspCidrs {
						cidrs <- cidr
					}
				}()
				cspInstance.GetCidrRanges(ctx, cspCidrs, regionRegexString)
				log.Printf("done adding all CIDR ranges for %s to job queue", cspString)
			}
			wg.Wait()
			close(cidrs)
		}()

		taskCounter := 0x00
		for cidr := range subCidrs {
			data, err := json.Marshal(cidr)
			if err != nil {
				log.Fatalf("error marshalling CidrRange to JSON. error = %v", err)
			}
			rdb.LPush(ctx, jobTaskQueue, data)
			taskCounter += 1
		}
		log.Printf("task queue: %s", jobTaskQueue)
		listLength := rdb.LLen(ctx, jobTaskQueue).Val()
		log.Printf("task queue size      : %d", listLength)
		log.Printf("adding job to the job queue")
		jobData, err := json.Marshal(job)
		if err != nil {
			log.Errorf("error marshalling job details into JSON. error = %v", err)
		}
		if length, err := rdb.LPush(ctx, SSLSEARCH_JOB_QUEUE_TODO, jobData).Result(); err != nil {
			log.Errorf("error adding job to job queue. error = %v", err)
		} else {
			log.Infof("job queue size: %d", length)
		}
	},
}

func init() {
	workerCmd.AddCommand(addCmd)
	addCmd.PersistentFlags().StringVarP(&regionRegexString, "region-regex", "r", ".*", "regex of cloud service provider region to search")
	addCmd.PersistentFlags().StringVar(&targetCsps, "target", "aws", "target cloud service providers list")
	addCmd.PersistentFlags().StringVar(&jobName, "job-name", "", "job name to be put in job queue")
	addCmd.PersistentFlags().StringVar(&jobDescription, "job-description", "", "job description to be put in job queue")
	addCmd.PersistentFlags().StringVar(&jobExportIndex, "job-export-index", "", "job export index in elasticsearch")
}

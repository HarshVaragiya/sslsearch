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
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add jobs to worker queue",
	Run: func(cmd *cobra.Command, args []string) {

		rdb := redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})

		cspStrings := strings.Split(workerTargets, ",")
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
				cspInstance.GetCidrRanges(ctx, cspCidrs, ".*")
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
			rdb.LPush(ctx, applicationNamespace, data)
			taskCounter += 1
		}
		listLength := rdb.LLen(ctx, applicationNamespace).Val()
		log.Printf("done adding all sub-cidr ranges to job queue.")
		log.Printf("tasks added to queue : %d", taskCounter)
		log.Printf("task queue size      : %d", listLength)
	},
}

func init() {
	workerCmd.AddCommand(addCmd)
	viper.AutomaticEnv()
	addCmd.PersistentFlags().StringVar(&workerTargets, "worker-targets", "aws", "target cloud service providers")
}

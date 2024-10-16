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
	"github.com/spf13/cobra"
)

var (
	redisConnectionString string
	applicationNamespace  string
	workerTargets         string
)

// workerCmd represents the worker command
var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "sslsearch worker subcommand",
	Long:  `used to run sslearch as worker to execute background jobs`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.AddCommand(workerCmd)
	workerCmd.PersistentFlags().StringVar(&redisConnectionString, "redis.host", "", "redis host url")
	workerCmd.PersistentFlags().StringVar(&applicationNamespace, "app.namespace", "sslsearch-tasks", "application namespace")
	workerCmd.MarkFlagRequired("redis.host")
}

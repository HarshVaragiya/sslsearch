/*
Copyright © 2023 Harsh Varagiya

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
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

var (
	debugFlag          bool
	keywordRegexString string
	regionRegexString  string
	portsString        string

	threadCount            int
	cidrSuffixPerGoRoutine int

	serverHeaderThreadCount    int
	jarmFingerprintThreadCount int

	// Export Configuration
	diskExport                  bool
	diskFilePath                string
	cassandraExport             bool
	cassandraConnectionString   string
	cassandraKeyspaceDotTable   string
	cassandraRecordTimeStampKey string
	elasticsearchExport         bool
	elasticsearchHost           string
	elasticsearchUsername       string
	elasticsearchPassword       string
	elasticsearchIndex          string
)

var (
	log                     = logrus.New()
	cidrRangesToScan        = atomic.Int64{}
	cidrRangesScanned       = atomic.Int64{}
	ipsScanned              = atomic.Int64{}
	ipScanRate              = atomic.Int64{}
	totalFindings           = atomic.Int64{}
	jarmFingerprintsGrabbed = atomic.Int64{}
	jarmFingerprintsScanned = atomic.Int64{}
	serverHeadersGrabbed    = atomic.Int64{}
	serverHeadersScanned    = atomic.Int64{}
	resultsExported         = atomic.Int64{}
	resultsProcessed        = atomic.Int64{}
	jarmRetryCount          = 3
	tcpTimeout              = 10
	consoleRefreshSeconds   = 5000

	state = 1

	httpClientPool = sync.Pool{
		New: func() interface{} {
			return &fasthttp.Client{
				TLSConfig: &tls.Config{
					// for server header check skip SSL validation
					InsecureSkipVerify: true,
				},
			}
		},
	}
	dialerPool = sync.Pool{
		New: func() interface{} {
			return &net.Dialer{
				Timeout: time.Duration(tcpTimeout) * time.Second,
			}
		},
	}
	tlsConfigPool = sync.Pool{
		New: func() interface{} {
			return &tls.Config{
				InsecureSkipVerify: true,
			}
		},
	}
	errConn         = fmt.Errorf("could not connect to remote host")
	errNoTls        = fmt.Errorf("could not find TLS on remote port")
	errNoMatch      = fmt.Errorf("certificate details did not match requirement")
	errCtxCancelled = fmt.Errorf("parent context cancelled")
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sslsearch",
	Short: "hunt for keywords in SSL certificates on cloud",
	Long: `search cloud providers / IP ranges to scan for interesting keywords in
SSL certificates. Do some initial recon for the findings if required. 
Initial Recon: 
	1. Server Header Grabbing
	2. JARM Fingerprinting`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sslsearch.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	// refined input flags
	rootCmd.PersistentFlags().StringVarP(&keywordRegexString, "keyword-regex", "k", ".*", "case insensitive keyword regex to search in subject or SAN (ex: .*amazon.* or .* which matches all)")
	rootCmd.PersistentFlags().StringVarP(&portsString, "ports", "p", "443", "ports to search")
	rootCmd.PersistentFlags().IntVarP(&threadCount, "threads", "t", 1000, "number of parallel threads to use")
	rootCmd.PersistentFlags().IntVar(&consoleRefreshSeconds, "refresh", 5, "console progress refresh in seconds")
	rootCmd.PersistentFlags().BoolVarP(&debugFlag, "debug", "v", false, "enable debug logs")
	rootCmd.PersistentFlags().IntVar(&cidrSuffixPerGoRoutine, "suffix", 4, "CIDR suffix per goroutine [each thread will scan 2^x IPs]")
	rootCmd.PersistentFlags().IntVar(&tcpTimeout, "timeout", 10, "tcp connection timeout in seconds")

	// Export to disk
	rootCmd.PersistentFlags().BoolVar(&diskExport, "export.disk", false, "export findings to disk")
	rootCmd.PersistentFlags().StringVarP(&diskFilePath, "export.disk.filename", "o", "", "output file name on disk")
	rootCmd.MarkFlagsRequiredTogether("export.disk", "export.disk.filename")

	// Export to cassandra
	rootCmd.PersistentFlags().BoolVar(&cassandraExport, "export.cassandra", false, "export findings to cassandra")
	rootCmd.PersistentFlags().StringVar(&cassandraConnectionString, "export.cassandra.connection-string", "", "cassandra connection string")
	rootCmd.PersistentFlags().StringVar(&cassandraKeyspaceDotTable, "export.cassandra.table", "recon.sslsearch", "cassandra keyspace.table name to store data")
	rootCmd.PersistentFlags().StringVar(&cassandraRecordTimeStampKey, "export.cassandra.result-ts-key", "", "cassandra default result timestamp key (defaults to YYYY-MM-DD)")
	rootCmd.MarkFlagsRequiredTogether("export.cassandra", "export.cassandra.connection-string")

	// Export to elasticsearch
	rootCmd.PersistentFlags().BoolVar(&elasticsearchExport, "export.elastic", false, "export findings to elasticsearch")
	rootCmd.PersistentFlags().StringVar(&elasticsearchHost, "export.elastic.host", "", "elasticsearch host where data will be sent")
	rootCmd.PersistentFlags().StringVar(&elasticsearchUsername, "export.elastic.username", "", "elasticsearch username for authentication")
	rootCmd.PersistentFlags().StringVar(&elasticsearchPassword, "export.elastic.password", "", "elasticsearch password for authentication")
	rootCmd.PersistentFlags().StringVar(&elasticsearchIndex, "export.elastic.index", "", "elasticsearch index where data will be stored (default: sslsearch-YYYY-MM-DD)")
	rootCmd.MarkFlagsRequiredTogether("export.elastic", "export.elastic.host", "export.elastic.username", "export.elastic.password")

	rootCmd.MarkFlagsMutuallyExclusive("export.disk", "export.elastic", "export.cassandra")

	// Recon flags
	rootCmd.PersistentFlags().IntVar(&serverHeaderThreadCount, "server-header-threads", 40, "number of threads to use for server header result enrichment")
	rootCmd.PersistentFlags().IntVar(&jarmRetryCount, "jarm-retry-count", 3, "retry attempts for JARM fingerprint")
	rootCmd.PersistentFlags().IntVar(&jarmFingerprintThreadCount, "jarm-threads", 40, "number of threads to use for JARM fingerprint enrichment (>200 might not be stable)")

}

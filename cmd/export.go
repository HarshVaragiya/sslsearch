package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
	"github.com/gocql/gocql"
	"github.com/sirupsen/logrus"
)

func SaveResultsToDisk(resultChan chan *CertResult, resultWg *sync.WaitGroup, outFileName string, consoleout bool) {
	outFile, err := os.OpenFile(outFileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.WithFields(logrus.Fields{"state": "save", "errmsg": err}).Fatalf("error opening output file")
	}
	defer resultWg.Done()
	enc := json.NewEncoder(outFile)
	for result := range resultChan {
		if err := enc.Encode(result); err != nil {
			log.WithFields(logrus.Fields{"state": "save", "subject": result.Subject, "SANs": fmt.Sprintf("%s", result.SANs), "errmsg": err}).Error("error saving result to disk")
		}
		if consoleout {
			logToConsole(result)
		} else {
			log.WithFields(
				logrus.Fields{
					"state":   "save",
					"cloud":   result.CSP,
					"region":  result.Region,
					"subject": result.Subject,
					"SANs":    fmt.Sprintf("%s", result.SANs),
					"jarm":    result.JARM,
					"port":    result.Port,
					"server":  result.ServerHeader}).Debug(result.Ip)
		}
	}
}

func ExportResultsToElasticsearch(resultChan chan *CertResult, resultWg *sync.WaitGroup, consoleout bool) {
	defer resultWg.Done()
	client, err := elasticsearch.NewTypedClient(elasticsearch.Config{
		Addresses:     []string{elasticsearchHost},
		Username:      elasticsearchUsername,
		Password:      elasticsearchPassword,
		EnableMetrics: true,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})
	if err != nil {
		log.Fatalf("error connecting to elasticsearch. error = %v", err)
	}
	if _, err := client.Indices.Create(elasticsearchIndex).Do(context.TODO()); err != nil {
		log.Fatalf("error creating elasticsearch index. error = %v", err)
	}
	log.Infof("exporting to elasticsearch on %s index: %s", elasticsearchHost, elasticsearchIndex)
	for result := range resultChan {
		if _, err = client.Index(elasticsearchIndex).Request(result).Do(context.TODO()); err != nil {
			log.Errorf("error exporting result to elasticsearch. error = %v", err)
		}
	}

}

func ExportResultsToCassandra(resultChan chan *CertResult, resultWg *sync.WaitGroup, consoleout bool) {
	defer resultWg.Done()
	cluster := gocql.NewCluster(cassandraConnectionString)
	cluster.Timeout = time.Second * 30
	s := strings.Split(cassandraKeyspace_Table, ".")
	cluster.Keyspace = s[0]
	table := s[1]
	session, err := cluster.CreateSession()
	log.Infof("exporting to cassandra with RecordTsKey: %s", cassandraRecordTimeStampKey)
	if err != nil {
		log.Fatalf("error connecting to cassandra. error = %v", err)
	}
	for result := range resultChan {
		if err = insertRecord(session, table, cassandraRecordTimeStampKey, result); err != nil {
			log.Fatalf("error writing to cassandra. error = %v", err)
		}
		if consoleout {
			logToConsole(result)
		}
	}
}

func insertRecord(session *gocql.Session, tableName string, record_ts string, result *CertResult) error {
	query := session.Query(
		fmt.Sprintf("INSERT INTO %s (record_ts, csp, region, ip, port, subject, scan_ts, issuer, sans, server_header, jarm, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tableName),
		record_ts, result.CSP, result.Region, result.Ip, result.Port, result.Subject, result.Timestamp, result.Issuer, result.SANs, result.ServerHeader, result.JARM, result.Meta,
	)
	if err := query.Exec(); err != nil {
		return fmt.Errorf("failed to execute query: %v", err)
	}
	return nil
}

func logToConsole(result *CertResult) {
	log.WithFields(
		logrus.Fields{
			"state":   "save",
			"cloud":   result.CSP,
			"region":  result.Region,
			"subject": result.Subject,
			"SANs":    fmt.Sprintf("%s", result.SANs),
			"jarm":    result.JARM,
			"port":    result.Port,
			"server":  result.ServerHeader}).Info(result.Ip)
}

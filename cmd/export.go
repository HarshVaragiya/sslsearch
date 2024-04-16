package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gocql/gocql"
	"github.com/sirupsen/logrus"
)

func SaveResultsToDisk(resultChan chan *CertResult, resultWg *sync.WaitGroup, outFile *os.File, consoleout bool) {
	defer resultWg.Done()
	enc := json.NewEncoder(outFile)
	for result := range resultChan {
		if err := enc.Encode(result); err != nil {
			log.WithFields(logrus.Fields{"state": "save", "subject": result.Subject, "SANs": fmt.Sprintf("%s", result.SANs)}).Error("error saving result to disk")
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
					"server":  result.ServerHeader}).Debug(result.RemoteAddr)
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
		fmt.Sprintf("INSERT INTO %s (record_ts, csp, region, remote_addr, subject, scan_ts, issuer, sans, server_header, jarm, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tableName),
		record_ts, result.CSP, result.Region, result.RemoteAddr, result.Subject, result.Timestamp, result.Issuer, result.SANs, result.ServerHeader, result.JARM, result.Meta,
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
			"server":  result.ServerHeader}).Info(result.RemoteAddr)
}

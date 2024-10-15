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

type Elasticsearch struct {
	elasticHost  string
	elasticUser  string
	elasticPass  string
	elasticIndex string
	client       *elasticsearch.TypedClient
}

func NewElasticsearch(elasticHost, elasticUser, elasticPass, elasticIndex string) (*Elasticsearch, error) {
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
		log.WithFields(logrus.Fields{"state": "elastic", "errmsg": err}).Errorf("error creating elasticsearch client")
		return nil, err
	}
	return &Elasticsearch{
		elasticHost:  elasticsearchHost,
		elasticUser:  elasticsearchUsername,
		elasticPass:  elasticsearchPassword,
		elasticIndex: elasticsearchIndex,
		client:       client,
	}, nil
}

func (es *Elasticsearch) Export(ctx context.Context, resultChan chan *CertResult, resultWg *sync.WaitGroup) error {
	defer resultWg.Done()
	if _, err := es.client.Indices.Create(elasticsearchIndex).Do(ctx); err != nil {
		log.WithFields(logrus.Fields{"state": "elastic"}).Errorf("error creating elasticsearch index. error = %v", err)
	}
	log.WithFields(logrus.Fields{"state": "elastic"}).Infof("exporting to elasticsearch on %s index: %s", elasticsearchHost, elasticsearchIndex)
	for result := range resultChan {
		if _, err := es.client.Index(elasticsearchIndex).Request(result).Do(ctx); err != nil {
			log.WithFields(logrus.Fields{"state": "elastic"}).Errorf("error exporting result to elasticsearch. error = %v", err)
		}
		resultsProcessed.Add(1)
	}
	return nil
}

type DiskTarget struct {
	filename string
	outfile  *os.File
}

func NewDiskTarget(filename string) (*DiskTarget, error) {
	outfile, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.WithFields(logrus.Fields{"state": "disk", "errmsg": err}).Errorf("error opening output file")
		return nil, err
	}
	return &DiskTarget{filename: filename, outfile: outfile}, nil
}

func (tg *DiskTarget) Export(ctx context.Context, resultChan chan *CertResult, resultWg *sync.WaitGroup) error {
	defer resultWg.Done()
	defer tg.outfile.Close()
	enc := json.NewEncoder(tg.outfile)
	log.WithFields(logrus.Fields{"state": "disk"}).Infof("exporting to file: %s", tg.filename)
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, ok := <-resultChan:
			if !ok {
				return nil
			}
			if err := enc.Encode(result); err != nil {
				log.WithFields(logrus.Fields{"state": "disk", "errmsg": err}).Errorf("error exporting result")
			}
			resultsProcessed.Add(1)
		}
	}
}

type Cassandra struct {
	session            *gocql.Session
	tableName          string
	recordTimestampKey string
}

func NewCassandra(connectionString, keyspaceTableName, recordTimestampKey string) (*Cassandra, error) {
	cluster := gocql.NewCluster(connectionString)
	cluster.Timeout = time.Second * 30
	s := strings.Split(keyspaceTableName, ".")
	cluster.Keyspace = s[0]
	tableName := s[1]
	session, err := cluster.CreateSession()
	return &Cassandra{session, tableName, recordTimestampKey}, err
}
func (ca *Cassandra) Export(ctx context.Context, resultChan chan *CertResult, resultWg *sync.WaitGroup) error {
	defer resultWg.Done()
	log.WithFields(logrus.Fields{"state": "cassandra"}).Infof("exporting to cassandra with RecordTsKey: %s", cassandraRecordTimeStampKey)
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, ok := <-resultChan:
			if !ok {
				return nil
			}
			if err := insertRecordIntoCassandra(ca.session, ca.tableName, cassandraRecordTimeStampKey, result); err != nil {
				log.WithFields(logrus.Fields{"state": "cassandra", "errmsg": err}).Errorf("error inserting record into cassandra")
			}
			resultsProcessed.Add(1)
		}
	}
}

func insertRecordIntoCassandra(session *gocql.Session, tableName string, record_ts string, result *CertResult) error {
	query := session.Query(
		fmt.Sprintf("INSERT INTO %s (record_ts, csp, region, ip, port, subject, scan_ts, issuer, sans, server_header, jarm, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tableName),
		record_ts, result.CSP, result.Region, result.Ip, result.Port, result.Subject, result.Timestamp, result.Issuer, result.SANs, result.ServerHeader, result.JARM, result.Meta,
	)
	if err := query.Exec(); err != nil {
		return fmt.Errorf("failed to execute query: %v", err)
	}
	return nil
}

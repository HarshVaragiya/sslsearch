package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"compress/gzip"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/gocql/gocql"
	"github.com/sirupsen/logrus"
)

func intPtr(i int) *int {
	return &i
}

func GetExportTarget() ExportTarget {
	if diskExport {
		tg, err := NewDiskTarget(diskFilePath)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "export", "type": "disk", "errmsg": err}).Fatalf("error configuring disk export target")
		}
		return tg
	}
	if cassandraExport {
		tg, err := NewCassandra(cassandraConnectionString, cassandraKeyspaceDotTable, cassandraRecordTimeStampKey)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "export", "type": "cassandra", "errmsg": err}).Fatalf("error configuring cassandra export target")
		}
		return tg
	}
	if elasticsearchExport {
		tg, err := NewElasticsearch(elasticsearchHost, elasticsearchUsername, elasticsearchPassword, elasticsearchIndex)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "export", "type": "elastic", "errmsg": err}).Fatalf("error configuring elasticsearch export target")
		}
		return tg
	}
	return nil
}

type Elasticsearch struct {
	elasticHost  string
	elasticUser  string
	elasticPass  string
	elasticIndex string
	client       *elasticsearch.Client
	indexer      esutil.BulkIndexer
}

func NewElasticsearch(elasticHost, elasticUser, elasticPass, elasticIndex string) (*Elasticsearch, error) {
	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses:                []string{elasticHost},
		Username:                 elasticUser,
		Password:                 elasticPass,
		EnableMetrics:            true,
		RetryBackoff:             func(i int) time.Duration { return time.Duration(i*10) * time.Second },
		MaxRetries:               15,
		CompressRequestBody:      true,
		CompressRequestBodyLevel: gzip.BestCompression,
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
	indexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:     client,       // The Elasticsearch client
		Index:      elasticIndex, // The default index name
		NumWorkers: 1,            // The number of worker goroutines (default: number of CPUs)
		FlushBytes: 8e+6,         // The flush threshold in bytes 1M
	})
	if err != nil {
		log.WithFields(logrus.Fields{"state": "elastic", "errmsg": err}).Errorf("error creating elasticsearch bulk indexer")
		return nil, err
	}
	log.WithFields(logrus.Fields{"state": "elastic"}).Infof("exporting to elasticsearch at: %s", elasticsearchHost)
	return &Elasticsearch{
		elasticHost:  elasticHost,
		elasticUser:  elasticUser,
		elasticPass:  elasticPass,
		elasticIndex: elasticIndex,
		client:       client,
		indexer:      indexer,
	}, nil
}

func (es *Elasticsearch) Export(resultChan chan *CertResult, resultWg *sync.WaitGroup) error {
	defer resultWg.Done()
	indexSettings := map[string]interface{}{
		"settings": map[string]interface{}{
			"number_of_shards": 20,
			"mapping": map[string]interface{}{
				"total_fields": map[string]interface{}{
					"limit": 60000,
				},
			},
		},
	}
	body, _ := json.Marshal(indexSettings)
	resp, err := es.client.Indices.Create(es.elasticIndex, es.client.Indices.Create.WithBody(
		bytes.NewReader(body),
	))
	if err != nil {
		log.WithFields(logrus.Fields{"state": "elastic", "errmsg": err}).Fatal("error creating elasticsearch index")
	} else if resp.IsError() && resp.StatusCode != 400 {
		log.WithFields(logrus.Fields{"state": "elastic", "errmsg": resp.String()}).Fatal("error creating elasticsearch index. invalid response")
	}
	log.WithFields(logrus.Fields{"state": "elastic"}).Infof("exporting to elasticsearch index: %s", es.elasticIndex)
	for result := range resultChan {
		resultBytes, err := json.Marshal(result)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "elastic", "errmsg": err}).Infof("error marshalling result to JSON")

		}
		err = es.indexer.Add(context.TODO(), esutil.BulkIndexerItem{
			Action: "index",
			Body:   bytes.NewReader(resultBytes),
			OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem) {
				resultsExported.Add(1)
			},
			OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, item2 esutil.BulkIndexerResponseItem, err error) {
				log.WithFields(logrus.Fields{"state": "elastic", "errmsg": err}).Errorf("error exporting result to elasticsearch")
			},
		})
		if err != nil {
			log.WithFields(logrus.Fields{"state": "elastic", "errmsg": err}).Errorf("error exporting result to elasticsearch")
		}
		resultsProcessed.Add(1)
	}
	if err := es.indexer.Close(context.TODO()); err != nil {
		log.WithFields(logrus.Fields{"state": "elastic", "errmsg": err}).Errorf("error flusing bulk indexer")
	}
	stats := es.indexer.Stats()
	log.WithFields(logrus.Fields{"state": "elastic"}).Infof("indexed %d documents with %d errors", stats.NumFlushed, stats.NumFailed)
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

func (tg *DiskTarget) Export(resultChan chan *CertResult, resultWg *sync.WaitGroup) error {
	defer resultWg.Done()
	defer tg.outfile.Close()
	enc := json.NewEncoder(tg.outfile)
	log.WithFields(logrus.Fields{"state": "disk"}).Infof("exporting to file: %s", tg.filename)
	for result := range resultChan {
		if err := enc.Encode(result); err != nil {
			log.WithFields(logrus.Fields{"state": "disk", "errmsg": err}).Errorf("error exporting result")
		} else {
			resultsExported.Add(1)
		}
		resultsProcessed.Add(1)
	}
	return nil
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
func (ca *Cassandra) Export(resultChan chan *CertResult, resultWg *sync.WaitGroup) error {
	defer resultWg.Done()
	log.WithFields(logrus.Fields{"state": "cassandra"}).Infof("exporting to cassandra with RecordTsKey: %s", cassandraRecordTimeStampKey)
	for result := range resultChan {
		if err := insertRecordIntoCassandra(ca.session, ca.tableName, cassandraRecordTimeStampKey, result); err != nil {
			log.WithFields(logrus.Fields{"state": "cassandra", "errmsg": err}).Errorf("error inserting record into cassandra")
		} else {
			resultsExported.Add(1)
		}
		resultsProcessed.Add(1)
	}
	return nil
}

func insertRecordIntoCassandra(session *gocql.Session, tableName string, record_ts string, result *CertResult) error {
	query := session.Query(
		fmt.Sprintf("INSERT INTO %s (record_ts, csp, region, ip, port, subject, scan_ts, issuer, sans, server_header, jarm, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tableName),
		record_ts, result.CSP, result.Region, result.Ip, result.Port, result.Subject, result.Timestamp, result.Issuer, result.SANs, result.Server, result.JARM, result.Meta,
	)
	if err := query.Exec(); err != nil {
		return fmt.Errorf("failed to execute query: %v", err)
	}
	return nil
}

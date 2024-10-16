package cmd

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
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
	client       *elasticsearch.TypedClient
}

func NewElasticsearch(elasticHost, elasticUser, elasticPass, elasticIndex string) (*Elasticsearch, error) {
	client, err := elasticsearch.NewTypedClient(elasticsearch.Config{
		Addresses:                []string{elasticsearchHost},
		Username:                 elasticsearchUsername,
		Password:                 elasticsearchPassword,
		EnableMetrics:            true,
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
	return &Elasticsearch{
		elasticHost:  elasticsearchHost,
		elasticUser:  elasticsearchUsername,
		elasticPass:  elasticsearchPassword,
		elasticIndex: elasticsearchIndex,
		client:       client,
	}, nil
}

func (es *Elasticsearch) Export(resultChan chan *CertResult, resultWg *sync.WaitGroup) error {
	defer resultWg.Done()
	indexSettings := &types.IndexSettings{
		Mapping: &types.MappingLimitSettings{
			TotalFields: &types.MappingLimitSettingsTotalFields{
				Limit: intPtr(50000),
			},
		},
		NumberOfShards: "10",
	}
	req := es.client.Indices.Create(es.elasticIndex)
	req.Settings(indexSettings)
	if _, err := req.Do(context.TODO()); err != nil {
		log.WithFields(logrus.Fields{"state": "elastic"}).Errorf("error creating elasticsearch index. error = %v", err)
	}
	log.WithFields(logrus.Fields{"state": "elastic"}).Infof("exporting to elasticsearch index: %s", elasticsearchIndex)
	for result := range resultChan {
		if _, err := es.client.Index(elasticsearchIndex).Request(result).Do(context.TODO()); err != nil {
			log.WithFields(logrus.Fields{"state": "elastic"}).Errorf("error exporting result to elasticsearch. error = %v", err)
		} else {
			resultsExported.Add(1)
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

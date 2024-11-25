package cmd

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"time"
)

const STATS_TTL = time.Minute * 10

func ExportStatsPeriodically(ctx context.Context, rdb *redis.Client, job *Job, hostname string, interval time.Duration) {
	prefix := fmt.Sprintf("sslsearch:workers:stats:%s", hostname)
	for {
		log.WithFields(logrus.Fields{"state": "stats", "type": "mgmt"}).Debugf("updating stats in redis")
		rdb.SAdd(ctx, fmt.Sprintf("sslsearch:workers:exec:%s", job.JobId), hostname)
		// update the job-id we are working on and all the associated statistics of the worker
		ExportStatsToRedis(ctx, rdb, prefix)
		time.Sleep(interval)
	}
}

func ExportStatsToRedis(ctx context.Context, rdb *redis.Client, redisKeyPrefix string) {
	rdb.Set(ctx, fmt.Sprintf("%s:cidr-ranges-to-scan", redisKeyPrefix), cidrRangesToScan.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:cidr-ranges-scanned", redisKeyPrefix), cidrRangesScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:ips-to-scan", redisKeyPrefix), ipsToScan.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:ips-err-conn", redisKeyPrefix), ipsErrConn.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:ips-err-no-tls", redisKeyPrefix), ipsErrNoTls.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:ips-scanned", redisKeyPrefix), ipsScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:total-findings", redisKeyPrefix), totalFindings.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:server-headers-grabbed", redisKeyPrefix), serverHeadersGrabbed.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:server-headers-scanned", redisKeyPrefix), serverHeadersScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:jarm-fingerprints-grabbed", redisKeyPrefix), jarmFingerprintsGrabbed.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:jarm-fingerprints-scanned", redisKeyPrefix), jarmFingerprintsScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:results-exported", redisKeyPrefix), resultsExported.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:results-processed", redisKeyPrefix), resultsProcessed.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:active-jarm-threads", redisKeyPrefix), activeJarmThreads.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:active-header-threads", redisKeyPrefix), activeHeaderThreads.Load(), STATS_TTL)
}

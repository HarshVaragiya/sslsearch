package cmd

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"time"
)

const STATS_TTL = time.Minute * 10

func ExportStatsPeriodically(ctx context.Context, rdb *redis.Client, job *Job, prefix string, interval time.Duration) {
	for {
		log.WithFields(logrus.Fields{"state": "stats", "type": "mgmt"}).Debugf("updating stats in redis")
		rdb.Set(ctx, fmt.Sprintf("%s:job-id", prefix), job.JobId, STATS_TTL)
		// update the job-id we are working on and all the associated statistics of the worker
		ExportStatsToRedis(ctx, rdb, prefix)
		time.Sleep(interval)
	}
}

func ExportStatsToRedis(ctx context.Context, rdb *redis.Client, redisKeyPrefix string) {
	rdb.Set(ctx, fmt.Sprintf("%s:stats:cidr-ranges-to-scan", redisKeyPrefix), cidrRangesToScan.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:cidr-ranges-scanned", redisKeyPrefix), cidrRangesScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:ips-to-scan", redisKeyPrefix), ipsToScan.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:ips-err-conn", redisKeyPrefix), ipsErrConn.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:ips-err-no-tls", redisKeyPrefix), ipsErrNoTls.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:ips-scanned", redisKeyPrefix), ipsScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:total-findings", redisKeyPrefix), totalFindings.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:server-headers-grabbed", redisKeyPrefix), serverHeadersGrabbed.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:server-headers-scanned", redisKeyPrefix), serverHeadersScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:jarm-fingerprints-grabbed", redisKeyPrefix), jarmFingerprintsGrabbed.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:jarm-fingerprints-scanned", redisKeyPrefix), jarmFingerprintsScanned.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:results-exported", redisKeyPrefix), resultsExported.Load(), STATS_TTL)
	rdb.Set(ctx, fmt.Sprintf("%s:stats:results-processed", redisKeyPrefix), resultsProcessed.Load(), STATS_TTL)
}

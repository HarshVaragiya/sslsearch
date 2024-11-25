package cmd

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"os"
	"runtime/pprof"
	"time"
)

func ProfileRuntime(ctx context.Context, rdb *redis.Client, hostname string) {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	accessKey := os.Getenv("ACCESS_KEY")
	secretKey := os.Getenv("SECRET_KEY")
	bucketName := os.Getenv("BUCKET_NAME")
	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	if err != nil || bucketName == "" {
		log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error connecting to MinIO server. exiting profiling")
		return
	}
	for {
		time.Sleep(time.Minute)
		keyPrefix, err := rdb.Get(ctx, "profile").Result()
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Debugf("error getting profile control variable")
			continue
		}
		log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt"}).Infof("attempting to profile application. prefix: %s", keyPrefix)
		cpuProfileTmpFileName := "/tmp/cpu-" + uuid.NewString() + ".prof"
		heapProfileTmpFileName := "/tmp/heap-" + uuid.NewString() + ".prof"
		cpuProfileFile, err := os.Create(cpuProfileTmpFileName)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error creating tmp file for CPU profiling")
			continue
		}
		heapProfileFile, err := os.Create(heapProfileTmpFileName)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error creating tmp file for HEAP profiling")
			continue
		}
		err = pprof.StartCPUProfile(cpuProfileFile)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error starting CPU profiling")
			continue
		}
		err = pprof.WriteHeapProfile(heapProfileFile)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error generating HEAP profile")
			continue
		}
		time.Sleep(time.Minute)
		pprof.StopCPUProfile()
		cpuProfileFile.Close()
		heapProfileFile.Close()
		cpuObjectName := fmt.Sprintf("%s/cpu/%s-%s.prof", keyPrefix, time.Now().Format("2006-01-02-15-04-05"), hostname)
		heapObjectName := fmt.Sprintf("%s/heap/%s-%s.prof", keyPrefix, time.Now().Format("2006-01-02-15-04-05"), hostname)
		info, err := minioClient.FPutObject(ctx, bucketName, cpuObjectName, cpuProfileTmpFileName, minio.PutObjectOptions{ContentType: "application/octet-stream"})
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error uploading profile to minio server")
			continue
		}
		log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt"}).Infof("uploaded CPU profile '%s' of size %d bytes", info.Key, info.Size)
		info, err = minioClient.FPutObject(ctx, bucketName, heapObjectName, heapProfileTmpFileName, minio.PutObjectOptions{ContentType: "application/octet-stream"})
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error uploading profile to minio server")
			continue
		}
		log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt"}).Infof("uploaded HEAP profile '%s' of size %d bytes", info.Key, info.Size)
		os.Remove(cpuProfileTmpFileName)
		os.Remove(heapProfileTmpFileName)
	}
}

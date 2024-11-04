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
	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	if err != nil {
		log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error connecting to MinIO server")
	}
	for {
		time.Sleep(time.Minute)
		keyPrefix, err := rdb.Get(ctx, "profile").Result()
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Debugf("error getting profile control variable")
			continue
		}
		log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt"}).Infof("attempting to profile application. prefix: %s", keyPrefix)
		tmpFileName := "/tmp/" + uuid.NewString() + ".prof"
		tmpFile, err := os.Create(tmpFileName)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error creating tmp file for profiling")
			continue
		}
		err = pprof.StartCPUProfile(tmpFile)
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error starting profiling")
			continue
		}
		time.Sleep(time.Minute)
		pprof.StopCPUProfile()
		tmpFile.Close()
		objectName := fmt.Sprintf("%s/%s-%s.prof", keyPrefix, time.Now().Format("2006-01-02-15-04-05"), hostname)
		info, err := minioClient.FPutObject(ctx, "projects-sslsearch", objectName, tmpFileName, minio.PutObjectOptions{ContentType: "application/octet-stream"})
		if err != nil {
			log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt", "errmsg": err}).Errorf("error uploading profile to minio server")
			continue
		}
		log.WithFields(logrus.Fields{"state": "profile", "type": "mgmt"}).Infof("uploaded profile '%s' of size %d bytes", info.Key, info.Size)
		os.Remove(tmpFileName)
	}
}

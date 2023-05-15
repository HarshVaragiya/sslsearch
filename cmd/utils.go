package cmd

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// perform sanity check on inputs
func CheckInputParameters() {
	if _, err := regexp.Compile(keywordRegexString); err != nil {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("could not compile keyword regex")
	}
}

func CheckRegionRegex() {
	if _, err := regexp.Compile(regionRegexString); err != nil {
		log.WithFields(logrus.Fields{"state": "main"}).Fatal("could not compile region regex")
	}
}

func UpdateLogLevel() {
	if traceFlag {
		log.SetLevel(logrus.TraceLevel)
		log.WithFields(logrus.Fields{"state": "main"}).Info("enabled trace logging")
	} else if debugFlag {
		log.SetLevel(logrus.DebugLevel)
		log.WithFields(logrus.Fields{"state": "main"}).Info("enabled debug logging")
	}
}

func PerformOutputChecks() {
	if _, err := os.Stat(outFileName); err == nil {
		if outputOverwrite {
			log.WithFields(logrus.Fields{"state": "main"}).Info("overwriting existing output file in 5 seconds")
			time.Sleep(5 * time.Second)
		} else {
			log.WithFields(logrus.Fields{"state": "main"}).Fatal("output file exists & overwrite flag not supplied!")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		log.WithFields(logrus.Fields{"state": "main"}).Debugf("output file does not exist and will be created")
	}
}

func RunScan() {
	// variables
	ports := strings.Split(portsString, ",")
	log.WithFields(logrus.Fields{"state": "main"}).Infof("parsed ports to scan: %s", ports)
	cidrChan := make(chan string, threadCount*5)
	resultChan := make(chan *CertResult, threadCount*2)
	var enrichedResultChan chan *CertResult
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

}

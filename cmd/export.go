package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

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
			log.WithFields(
				logrus.Fields{
					"state":   "save",
					"cloud":   result.CSP,
					"region":  result.Region,
					"subject": result.Subject,
					"SANs":    fmt.Sprintf("%s", result.SANs),
					"jarm":    result.JARM,
					"server":  result.ServerHeader}).Info(result.RemoteAddr)
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

func ExportResultsToCassandra(resultChan chan *CertResult, resultWg *sync.WaitGroup, connstr string, consoleout bool) {

}

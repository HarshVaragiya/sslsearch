package cmd

import (
	"context"
	"sync"
	"time"
)

const (
	AWS_IP_RANGES_URL          = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	CLOUDFLARE_IPv4_RANGES_URL = "https://www.cloudflare.com/ips-v4"
	DIGITALOCEAN_IP_RANGES_URL = "https://www.digitalocean.com/geo/google.csv"
	GOOGLE_CLOUD_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
	ORACLE_CLOUD_IP_RANGES_URL = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"

	TOTAL_IPv4_ADDR_COUNT = 3706452992
)

type CidrRangeInput interface {
	GetCidrRanges(context.Context, chan CidrRange, string)
}

type ExportTarget interface {
	Export(resultChan chan *CertResult, resultWg *sync.WaitGroup) error
}

type CidrRange struct {
	Cidr   string `json:"cidr"`
	CSP    string `json:"csp"`
	Region string `json:"region"`
	Meta   string `json:"meta"`
}

type CertResult struct {
	Ip        string            `json:"ip"`
	Port      string            `json:"port"`
	Subject   string            `json:"subject"`
	Issuer    string            `json:"issuer"`
	SANs      []string          `json:"SANs"`
	JARM      string            `json:"jarm"`
	CSP       string            `json:"cloud"`
	Region    string            `json:"region"`
	Meta      string            `json:"metadata"`
	Timestamp time.Time         `json:"timestamp"`
	Headers   map[string]string `json:"headers"`
	Server    string            `json:"server"`
	Host      string            `json:"host"`
}

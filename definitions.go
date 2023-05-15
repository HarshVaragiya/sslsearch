package main

import (
	"context"
)

const (
	AWS_IP_RANGES_URL          = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	CLOUDFLARE_IPv4_RANGES_URL = "https://www.cloudflare.com/ips-v4"
	DIGITALOCEAN_IP_RANGES_URL = "https://digitalocean.com/geo/google.csv"
	GOOGLE_CLOUD_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
	ORACLE_CLOUD_IP_RANGES_URL = "https://docs.oracle.com/iaas/tools/public_ip_ranges.json"

	TOTAL_IPv4_ADDR_COUNT = 3706452992
)

type CidrRangeInput interface {
	GetCidrRanges(context.Context, chan string, string)
}

type CertResult struct {
	RemoteAddr   string   `json:"remote"`
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SANs         []string `json:"SANs"`
	ServerHeader string   `json:"server"`
	JARM         string   `json:"jarm"`
}

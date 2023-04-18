package main

import (
	"fmt"
	"net"
	"strings"
)

func GetCspInstance(cspString string) (CidrRangeInput, error) {
	cspString = strings.ToLower(cspString)
	if cspString == "aws" {
		return AWS{}, nil
	}
	return nil, fmt.Errorf("unknown cloud service provider")
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func getRemoteAddrString(ip, port string) string {
	return fmt.Sprintf("%v:%v", ip, port)
}

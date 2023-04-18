package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/seancfoley/ipaddress-go/ipaddr"
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

func SplitCIDR(cidrString string, suffixLenPerGoRoutine int, cidrChan chan string) error {
	cidr := ipaddr.NewIPAddressString(cidrString).GetAddress()
	cidrRange := cidr.GetPrefixLen().Len()
	adjustPrefixLength := 32 - cidrRange - suffixLenPerGoRoutine
	if adjustPrefixLength < 0 {
		adjustPrefixLength = 0
	}
	for i := cidr.AdjustPrefixLen(adjustPrefixLength).PrefixBlockIterator(); i.HasNext(); {
		nextCidr := i.Next().String()
		statsLock.Lock()
		cidrRangesToScan += 1
		statsLock.Unlock()
		cidrChan <- nextCidr
	}
	return nil
}

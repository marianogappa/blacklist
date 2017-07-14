package blacklist

import (
	"fmt"
	"strings"
	"sync"
)

// DNSChecker receives a list of BL domains (like zen.spamhaus.org) and provides
// the Status method for checking if an IP is listed on them
type DNSChecker struct {
	domains []string
	digger  *digger
}

// NewDNSChecker is the constructor for a DNSChecker
func NewDNSChecker(domains []string) *DNSChecker {
	return &DNSChecker{domains, &digger{}}
}

// Status looks for an A record for the supplied IPv4 address on all domains supplied to this DNSChecker
func (d *DNSChecker) Status(ipv4 string) (blacklists []string, errors []error) {
	var (
		sIP = strings.Split(ipv4, ".")
		rIP = fmt.Sprintf("%v.%v.%v.%v", sIP[3], sIP[2], sIP[1], sIP[0])
	)

	wg := sync.WaitGroup{}
	wg.Add(len(d.domains))
	for _, dm := range d.domains {
		go func(dm string) {
			defer wg.Done()
			bl, err := d.digger.digShort(rIP + "." + dm)
			if err != nil {
				errors = append(errors, err)
			}
			if bl {
				blacklists = append(blacklists, dm)
			}
		}(dm)
	}
	wg.Wait()
	return
}

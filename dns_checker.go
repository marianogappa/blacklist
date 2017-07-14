package blacklist

import (
	"fmt"
	"strings"
	"sync"
)

type DNSChecker struct {
	domains []string
	digger  *digger
}

func NewDNSChecker(domains []string) *DNSChecker {
	return &DNSChecker{domains, &digger{}}
}

func (d *DNSChecker) status(ipv4 string) (blacklists []string, errors []error) {
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

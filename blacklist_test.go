package blacklist

import (
	"reflect"
	"testing"
)

func TestBlacklist(t *testing.T) {
	var (
		d = NewDNSChecker([]string{
			"spam.dnsbl.sorbs.net",
		})
		ipv4            = "127.0.0.2"
		blacklists, err = d.Status(ipv4)
	)

	if !reflect.DeepEqual(blacklists, []string{"spam.dnsbl.sorbs.net"}) {
		t.Error("SORBS did not list 127.0.0.2. This *could* be a bug in the code, but also: no Internet, timeout, SORBS down, etc.")
		if err != nil {
			t.Logf("There was an error running the check: %f\n", err)
		}
	}
}

package blacklist

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type digger struct {
	nameserver string
	c          dns.Client
}

func (d *digger) digShort(dn string) (bool, error) {
	if d.nameserver == "" {
		d.loadNameserver()
	}
	d.c.Net = "udp"
	d.c.Timeout = 5 * time.Second

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Opcode:           dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}

	m.Rcode = dns.RcodeSuccess
	m.Question[0] = dns.Question{Name: dns.Fqdn(dn), Qtype: dns.TypeA, Qclass: uint16(dns.ClassINET)}
	m.Id = dns.Id()

	r, _, err := d.c.Exchange(m, d.nameserver)
	if err != nil {
		return false, err
	}
	if r.Id != m.Id {
		return false, fmt.Errorf("Id mismatch")
	}
	if len(r.Answer) == 0 {
		return false, nil
	}
	a := strings.Split(r.Answer[0].String(), "\t")
	if len(a) == 0 {
		return false, nil
	}
	// fmt.Println(a[len(a)-1]) // Use for debug. Should say 127.0.0.6, depending on compliance with RFC
	return true, nil
}

func (d *digger) loadNameserver() {
	var nameserver string
	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nameserver = "@" + conf.Servers[0]
	}

	nameserver = string([]byte(nameserver)[1:]) // chop off @
	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, strconv.Itoa(53))
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(53)
	}
	d.nameserver = nameserver
}

// egress-pin drops every connection a process's network namespace opens,
// except to one IP address.
//
// The rules go into that namespace rather than the host's ruleset: they leave
// with the namespace, and a process inside it without CAP_NET_ADMIN cannot
// take them out
package main

import (
	"errors"
	"flag"
	"log"
	"net/netip"
	"os"
	"strconv"
)

func main() {
	log.SetFlags(0)

	var pid pidFlag
	var ip ipFlag
	flag.Var(&pid, "pid", "process whose network namespace is pinned")
	flag.Var(&ip, "ip", "the one address it may connect to")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	if flag.NArg() != 0 || !pid.set || !ip.set {
		flag.Usage()
		os.Exit(2)
	}

	if err := pin(pid.value, ip.value); err != nil {
		log.Fatal(err)
	}
}

// Not the last of several: a second --ip would otherwise quietly replace the
// first, and the namespace be pinned to an address the caller did not mean
var errTwice = errors.New("given more than once")

type pidFlag struct {
	value int
	set   bool
}

func (f *pidFlag) String() string {
	if !f.set {
		return ""
	}
	return strconv.Itoa(f.value)
}

func (f *pidFlag) Set(s string) error {
	if f.set {
		return errTwice
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return errors.New("not a process id")
	}
	f.value, f.set = n, true
	return nil
}

type ipFlag struct {
	value netip.Addr
	set   bool
}

func (f *ipFlag) String() string {
	if !f.set {
		return ""
	}
	return f.value.String()
}

func (f *ipFlag) Set(s string) error {
	if f.set {
		return errTwice
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return errors.New("not an IP address")
	}
	// Not left as ::ffff:a.b.c.d: the packets it stands for carry the IPv4
	// address, and an IPv6 match would never see them
	f.value, f.set = a.Unmap(), true
	return nil
}

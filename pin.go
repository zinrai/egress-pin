package main

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func pin(pid int, ip netip.Addr) error {
	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return err
	}
	defer ns.Close()

	c, err := nftables.New(nftables.WithNetNSFd(int(ns.Fd())))
	if err != nil {
		return err
	}
	return apply(c, ip)
}

func apply(c *nftables.Conn, ip netip.Addr) error {
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "egress-pin"})
	// Not added to on a second run: emptied and refilled in the one batch, so
	// the pin is replaced
	c.FlushTable(t)
	drop := nftables.ChainPolicyDrop
	ch := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &drop,
	})
	for _, match := range [][]expr.Any{loopback(), replies(), destination(ip)} {
		c.AddRule(&nftables.Rule{
			Table: t,
			Chain: ch,
			Exprs: append(match, &expr.Verdict{Kind: expr.VerdictAccept}),
		})
	}
	return c.Flush()
}

// Not dropped: processes in the namespace talk to each other over it
func loopback() []expr.Any {
	name := make([]byte, unix.IFNAMSIZ)
	copy(name, "lo")
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name},
	}
}

// Not only what the process connects to: a connection made to it from
// outside, such as one to a port it listens on, has to be answered
func replies() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}

const (
	ipv4DstAddrOffset = 16
	ipv6DstAddrOffset = 24
)

func destination(ip netip.Addr) []expr.Any {
	proto, offset := byte(unix.NFPROTO_IPV4), uint32(ipv4DstAddrOffset)
	if ip.Is6() {
		proto, offset = byte(unix.NFPROTO_IPV6), uint32(ipv6DstAddrOffset)
	}
	addr := ip.AsSlice()
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(addr))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
	}
}

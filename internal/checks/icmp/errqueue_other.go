//go:build !linux

package icmp

import (
	"net"
	"net/netip"
	"syscall"
)

// errQueueEntry mirrors the Linux type. Other systems have no error queue on ICMP datagram sockets, so ICMP errors seen
// only through one are not reported there.
type errQueueEntry struct {
	errno   syscall.Errno
	local   bool
	typ     int
	code    int
	info    uint32
	from    netip.Addr
	payload []byte
}

func enableRecvErr(net.PacketConn, bool) error { return nil }

func drainErrQueue(net.PacketConn) []errQueueEntry { return nil }

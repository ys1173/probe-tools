//go:build linux

package icmp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// errQueueEntry is one error Linux queued for a datagram ICMP socket: an ICMP error from the network (origin icmp or
// icmp6), or a local one such as EMSGSIZE.
type errQueueEntry struct {
	errno   syscall.Errno
	local   bool
	typ     int
	code    int
	info    uint32 // the MTU for "fragmentation needed", "packet too big" and local EMSGSIZE
	from    netip.Addr
	payload []byte // the start of the ICMP message we sent, so the echo sequence can be read
}

// enableRecvErr asks the kernel to queue ICMP errors for the socket. A datagram ICMP socket otherwise drops them, and
// with it the only record of which router answered and why.
func enableRecvErr(conn net.PacketConn, v6 bool) error {
	return control(conn, func(fd int) error {
		if v6 {
			return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
		}
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	})
}

func control(conn net.PacketConn, f func(fd int) error) error {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return errors.New("socket does not expose its descriptor")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

// drainErrQueue reads everything waiting on the socket's error queue without blocking.
func drainErrQueue(conn net.PacketConn) []errQueueEntry {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	var out []errQueueEntry
	buf := make([]byte, 1500)
	oob := make([]byte, 512)
	for i := 0; i < 64; i++ { // a bound, in case something keeps queueing faster than we read
		var n, oobn int
		var rerr error
		err := rc.Read(func(fd uintptr) bool {
			n, oobn, _, _, rerr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			return true // never wait: an empty queue means we are done
		})
		if err != nil || rerr != nil {
			break
		}
		e, ok := parseErrQueue(buf[:n], oob[:oobn])
		if ok {
			out = append(out, e)
		}
	}
	return out
}

func parseErrQueue(payload, oob []byte) (errQueueEntry, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return errQueueEntry{}, false
	}
	for _, m := range msgs {
		if !((m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_RECVERR) ||
			(m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_RECVERR)) {
			continue
		}
		return parseExtendedErr(m.Data, payload)
	}
	return errQueueEntry{}, false
}

// parseExtendedErr reads struct sock_extended_err and the offender address that follows it.
func parseExtendedErr(d, payload []byte) (errQueueEntry, bool) {
	if len(d) < 16 {
		return errQueueEntry{}, false
	}
	ne := binary.NativeEndian
	e := errQueueEntry{
		errno:   syscall.Errno(ne.Uint32(d[0:4])),
		local:   d[4] == unix.SO_EE_ORIGIN_LOCAL,
		typ:     int(d[5]),
		code:    int(d[6]),
		info:    ne.Uint32(d[8:12]),
		payload: append([]byte(nil), payload...),
	}
	sa := d[16:]
	if len(sa) >= 2 {
		switch ne.Uint16(sa[0:2]) {
		case unix.AF_INET:
			if len(sa) >= 8 {
				e.from = netip.AddrFrom4([4]byte(sa[4:8]))
			}
		case unix.AF_INET6:
			if len(sa) >= 24 {
				e.from = netip.AddrFrom16([16]byte(sa[8:24])).Unmap()
			}
		}
	}
	return e, true
}

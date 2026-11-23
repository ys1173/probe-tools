//go:build unix

package icmp

import "syscall"

const tcpTraceSupported = true

// tcpControl sets the TTL on a TCP socket before it connects, and binds it to an ephemeral port first so the port (which
// an ICMP error quotes) is known before the SYN goes out. onPort is called with that port.
func tcpControl(v6 bool, ttl int, onPort func(int)) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var err error
		cerr := c.Control(func(fd uintptr) {
			s := int(fd)
			var sa syscall.Sockaddr
			if v6 {
				err = syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
				sa = &syscall.SockaddrInet6{}
			} else {
				err = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
				sa = &syscall.SockaddrInet4{}
			}
			if err != nil {
				return
			}
			if err = syscall.Bind(s, sa); err != nil {
				return
			}
			var got syscall.Sockaddr
			if got, err = syscall.Getsockname(s); err != nil {
				return
			}
			switch a := got.(type) {
			case *syscall.SockaddrInet4:
				onPort(a.Port)
			case *syscall.SockaddrInet6:
				onPort(a.Port)
			}
		})
		if cerr != nil {
			return cerr
		}
		return err
	}
}

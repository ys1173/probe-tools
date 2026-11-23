//go:build linux

package icmp

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

const pathMTUSupported = true

// setDontFragment forbids fragmentation on the socket. PMTUDISC_PROBE sets DF but ignores the kernel's cached path
// MTU, so each size is really put on the wire instead of being refused from a value learned earlier.
func setDontFragment(s *echoSock) error {
	return control(s.conn, func(fd int) error {
		if s.v6 {
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE); err != nil {
				return err
			}
			return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
		}
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
	})
}

func isMsgSize(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }

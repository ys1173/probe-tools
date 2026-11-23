//go:build !unix

package icmp

import (
	"errors"
	"syscall"
)

const tcpTraceSupported = false

func tcpControl(bool, int, func(int)) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return errors.New("tcp traceroute is not supported on this system")
	}
}

//go:build !linux

package icmp

import "errors"

// path_mtu needs Linux's per-socket don't-fragment options; elsewhere it reports CodeUnavailable.
const pathMTUSupported = false

func setDontFragment(*echoSock) error { return errors.New("not supported on this system") }

func isMsgSize(error) bool { return false }

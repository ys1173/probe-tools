//go:build linux

package icmp

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseExtendedErr(t *testing.T) {
	ne := binary.NativeEndian
	d := make([]byte, 16+16)
	ne.PutUint32(d[0:], uint32(syscall.EMSGSIZE))
	d[4] = unix.SO_EE_ORIGIN_ICMP
	d[5], d[6] = 3, 4
	ne.PutUint32(d[8:], 1400)
	ne.PutUint16(d[16:], unix.AF_INET)
	copy(d[20:24], []byte{10, 0, 0, 1})
	e, ok := parseExtendedErr(d, echoHdr(v4EchoRequest, 1, 9, nil))
	if !ok || e.errno != syscall.EMSGSIZE || e.local || e.typ != 3 || e.code != 4 || e.info != 1400 ||
		e.from != netip.MustParseAddr("10.0.0.1") || len(e.payload) != 8 {
		t.Fatalf("parsed %+v", e)
	}

	d6 := make([]byte, 16+28)
	d6[4] = unix.SO_EE_ORIGIN_ICMP6
	d6[5] = v6TimeExceeded
	ne.PutUint16(d6[16:], unix.AF_INET6)
	copy(d6[24:40], netip.MustParseAddr("2001:db8::9").AsSlice())
	e, ok = parseExtendedErr(d6, nil)
	if !ok || e.from != netip.MustParseAddr("2001:db8::9") || e.typ != v6TimeExceeded {
		t.Fatalf("parsed v6 %+v", e)
	}

	if _, ok := parseExtendedErr(d[:10], nil); ok {
		t.Fatal("short struct accepted")
	}
}

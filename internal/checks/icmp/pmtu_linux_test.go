//go:build linux

package icmp

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"probetools/internal/protocol"
)

// TestPathMTULoweredInterface lowers the MTU of the container's default-route interface, so sizes above it fail with
// EMSGSIZE and the search has to bisect. It changes an interface, so it runs only inside a throwaway container
// (/.dockerenv) with NET_ADMIN, which GO_PRIVILEGED=1 scripts/go test provides.
func TestPathMTULoweredInterface(t *testing.T) {
	needCap(t, "path_mtu")
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("not in a container; will not change an interface MTU")
	}
	iface := defaultIface(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	getMTU := func() uint32 {
		ifr, _ := unix.NewIfreq(iface)
		if err := unix.IoctlIfreq(fd, unix.SIOCGIFMTU, ifr); err != nil {
			t.Fatal(err)
		}
		return ifr.Uint32()
	}
	setMTU := func(v uint32) error {
		ifr, _ := unix.NewIfreq(iface)
		ifr.SetUint32(v)
		return unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr)
	}
	orig := getMTU()
	if err := setMTU(1400); err != nil {
		t.Skipf("cannot change the MTU of %s (needs NET_ADMIN): %v", iface, err)
	}
	t.Cleanup(func() { setMTU(orig) })

	gw := gatewayIPv4(t)
	for _, c := range []struct {
		kind sockKind
		cap  string
	}{{kindDgram, "unpriv_icmp"}, {kindRaw, "raw_icmp"}} {
		t.Run(c.kind.String(), func(t *testing.T) {
			needCap(t, c.cap)
			withKind(t, c.kind)
			res, perr := runCheck(t, testEnv(t), protocol.CheckPathMTU, protocol.PathMTUParams{Target: gw, MaxSize: 9000})
			if perr != nil {
				t.Fatal(perr)
			}
			r := res.(PathMTUResult)
			t.Logf("%+v", r)
			if r.PathMTU != 1400 || r.MaxSizeTested != 9000 || r.Attempts < 5 {
				t.Fatalf("result %+v", r)
			}
		})
	}
}

func defaultIface(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/net/route")
	if err != nil {
		t.Skip("no /proc/net/route")
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) > 7 && fl[1] == "00000000" && fl[7] == "00000000" {
			return fl[0]
		}
	}
	t.Skip("no default route")
	return ""
}

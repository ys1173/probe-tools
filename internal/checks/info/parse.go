package info

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// rtfGateway is RTF_GATEWAY from the Linux routing flags: the route goes through a next hop.
const rtfGateway = 0x2

// defaultGateways reads the kernel routing tables. Only Linux exposes them as files; elsewhere the field is omitted
// rather than guessed.
func defaultGateways() []Gateway {
	if runtime.GOOS != "linux" {
		return nil
	}
	var out []Gateway
	if f, err := os.Open("/proc/net/route"); err == nil {
		out = append(out, parseRoute4(f)...)
		f.Close()
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		out = append(out, parseRoute6(f)...)
		f.Close()
	}
	return out
}

// parseRoute4 parses /proc/net/route. Addresses there are hex in the host's byte order, which is little-endian on every
// platform the probe ships for; reading them as little-endian puts the octets back in network order.
func parseRoute4(r io.Reader) []Gateway {
	var out []Gateway
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header line
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfGateway == 0 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		gw, ok := hexIPv4(f[2])
		if !ok || gw.IsUnspecified() {
			continue
		}
		out = append(out, Gateway{Interface: f[0], Gateway: gw.String(), Family: "4"})
	}
	return out
}

func hexIPv4(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, false
	}
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(b))
	return netip.AddrFrom4(a), true
}

// parseRoute6 parses /proc/net/ipv6_route: destination, prefix length, source, source prefix length, next hop, metric,
// refcount, use, flags, interface. A default route has a zero destination and prefix length and a real next hop.
func parseRoute6(r io.Reader) []Gateway {
	var out []Gateway
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		if f[1] != "00" || strings.Trim(f[0], "0") != "" {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil || len(b) != 16 {
			continue
		}
		gw := netip.AddrFrom16([16]byte(b))
		if gw.IsUnspecified() {
			continue
		}
		out = append(out, Gateway{Interface: f[9], Gateway: gw.String(), Family: "6"})
	}
	return out
}

// dnsServers lists the nameserver lines of a resolv.conf. A missing file gives an empty list.
func dnsServers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	return parseResolvConf(f)
}

func parseResolvConf(r io.Reader) []string {
	out := []string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, a.String())
			}
		}
	}
	return out
}

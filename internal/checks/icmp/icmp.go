// Package icmp implements the network-layer checks: ping, traceroute and path_mtu, plus detection of what ICMP
// sockets the probe may open.
//
// Every check sends only to an address the probe's policy returned for the target. Routers that answer a traceroute
// along the way are never sent anything, so they are not policy-checked.
package icmp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// Register adds ping, traceroute and path_mtu to r.
func Register(r *check.Registry) {
	r.Register(protocol.CheckPing, runPing)
	r.Register(protocol.CheckTraceroute, runTraceroute)
	r.Register(protocol.CheckPathMTU, runPathMTU)
}

// Capabilities reports which ICMP sockets this process can open. The probe runtime calls it once at start-up.
//
//	raw_icmp, raw_icmp6       raw sockets (CAP_NET_RAW): needed by traceroute, used by ping as a fallback
//	unpriv_icmp, unpriv_icmp6 unprivileged datagram sockets (Linux net.ipv4.ping_group_range): preferred by ping
//	path_mtu                  path_mtu can run here (Linux, with either kind of socket)
func Capabilities() map[string]bool {
	try := func(network, addr string) bool {
		c, err := xicmp.ListenPacket(network, addr)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	caps := map[string]bool{
		"raw_icmp":     try("ip4:icmp", "0.0.0.0"),
		"unpriv_icmp":  try("udp4", "0.0.0.0"),
		"raw_icmp6":    try("ip6:ipv6-icmp", "::"),
		"unpriv_icmp6": try("udp6", "::"),
	}
	caps["path_mtu"] = pathMTUSupported && (caps["raw_icmp"] || caps["unpriv_icmp"])
	return caps
}

// Socket kinds. forceKind lets tests exercise the raw fallback on a host where datagram sockets also work.
type sockKind int

const (
	kindAuto sockKind = iota
	kindDgram
	kindRaw
)

var forceKind = kindAuto

func (k sockKind) String() string {
	if k == kindRaw {
		return "raw"
	}
	return "datagram"
}

// echoSock is an ICMP socket for sending echo requests: a datagram socket where the host allows it, else a raw one.
type echoSock struct {
	pc   *xicmp.PacketConn
	conn net.PacketConn // the socket under pc, for socket options and the error queue
	kind sockKind
	v6   bool
}

const fixNoICMP = "this probe can open no ICMP socket: grant it the NET_RAW capability (e.g. setcap cap_net_raw+ep, or " +
	"--cap-add NET_RAW in a container) or allow its group in net.ipv4.ping_group_range"

// openEcho opens a datagram ICMP socket, falling back to raw. caps is env.Capabilities: an explicit false skips a kind,
// a missing entry means unknown, so the socket is tried.
func openEcho(v6 bool, caps map[string]bool) (*echoSock, *protocol.Error) {
	kinds := []sockKind{kindDgram, kindRaw}
	if forceKind != kindAuto {
		kinds = []sockKind{forceKind}
	}
	s, err := openKinds(v6, caps, kinds)
	if err == nil {
		return s, nil
	}
	if !isPermission(err) {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "%s (last error: %v)", fixNoICMP, err)
	}
	return nil, protocol.Errorf(protocol.CodeUnavailable, "%s", fixNoICMP)
}

// openKinds opens the first kind of ICMP socket that works. When caps rules out every kind the error is a permission
// error, as that is what opening would have failed with.
func openKinds(v6 bool, caps map[string]bool, kinds []sockKind) (*echoSock, error) {
	suffix := ""
	if v6 {
		suffix = "6"
	}
	lastErr := error(os.ErrPermission)
	for _, k := range kinds {
		capName := "unpriv_icmp" + suffix
		network, addr := "udp4", "0.0.0.0"
		if k == kindRaw {
			capName = "raw_icmp" + suffix
			network = "ip4:icmp"
		}
		if v6 {
			addr = "::"
			if k == kindRaw {
				network = "ip6:ipv6-icmp"
			} else {
				network = "udp6"
			}
		}
		if ok, known := caps[capName]; known && !ok {
			continue
		}
		pc, err := xicmp.ListenPacket(network, addr)
		if err != nil {
			lastErr = err
			continue
		}
		s := &echoSock{pc: pc, kind: k, v6: v6}
		if v6 {
			s.conn = pc.IPv6PacketConn().PacketConn
			pc.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
		} else {
			s.conn = pc.IPv4PacketConn().PacketConn
			pc.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
		}
		return s, nil
	}
	return nil, lastErr
}

func (s *echoSock) Close() error { return s.pc.Close() }

// read returns one ICMP message (without IP header), the TTL or hop limit it arrived with (0 when unknown) and its
// source.
func (s *echoSock) read(b []byte) (int, int, netip.Addr, error) {
	var n, ttl int
	var src net.Addr
	var err error
	if s.v6 {
		var cm *ipv6.ControlMessage
		n, cm, src, err = s.pc.IPv6PacketConn().ReadFrom(b)
		if cm != nil {
			ttl = cm.HopLimit
		}
	} else {
		var cm *ipv4.ControlMessage
		n, cm, src, err = s.pc.IPv4PacketConn().ReadFrom(b)
		if cm != nil {
			ttl = cm.TTL
		}
	}
	if err != nil {
		return 0, 0, netip.Addr{}, err
	}
	return n, ttl, addrOf(src), nil
}

func (s *echoSock) writeTo(b []byte, dst netip.Addr) error {
	var to net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	if s.kind == kindDgram {
		to = &net.UDPAddr{IP: dst.AsSlice()}
	}
	_, err := s.pc.WriteTo(b, to)
	return err
}

func addrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return netip.Addr{}
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}

func isPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPROTONOSUPPORT)
}

// resolveTarget asks the policy for the target's addresses and takes the first: raw-socket checks send only there.
func resolveTarget(ctx context.Context, env *check.Env, target, family string) (netip.Addr, *protocol.Error) {
	if env.Policy == nil {
		return netip.Addr{}, protocol.Errorf(protocol.CodeInternal, "no target policy")
	}
	addrs, err := env.Policy.Resolve(ctx, target, family)
	if err != nil {
		return netip.Addr{}, err
	}
	return addrs[0], nil
}

// checkDeadline is when a check must have its answer ready: the job's deadline less a margin for sending the result,
// and never more than the 40 s one job may take.
func checkDeadline(ctx context.Context, now time.Time) time.Time {
	d := now.Add(time.Duration(protocol.MaxCheckBudgetMS)*time.Millisecond - time.Second)
	if cd, ok := ctx.Deadline(); ok {
		if cd = cd.Add(-300 * time.Millisecond); cd.Before(d) {
			d = cd
		}
	}
	return d
}

func ms(d time.Duration) float64 {
	return roundMS(float64(d) / float64(time.Millisecond))
}

func roundMS(v float64) float64 {
	return float64(int64(v*1000+0.5)) / 1000
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// errnoText gives the system's reason for a socket error without Go's operation prefix.
func errnoText(err error) string {
	var se *os.SyscallError
	if errors.As(err, &se) {
		return se.Err.Error()
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return errnoText(oe.Err)
	}
	return err.Error()
}

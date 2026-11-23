package pathtest

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

const (
	udpSends    = 3
	udpInterval = 200 * time.Millisecond
)

func pathSend(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.PathSendParams
	if err := check.Decode(raw, &p); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()

	// The name goes to the policy as given, so a closed policy that allows the receiver by allow_hosts still matches.
	address := net.JoinHostPort(p.Address, strconv.Itoa(p.Port))
	dial := func(ctx context.Context, network string) (net.Conn, error) {
		return env.Policy.DialContext(ctx, &net.Dialer{}, network, address)
	}
	if p.Protocol == "tcp" {
		return sendTCP(ctx, dial, p.Nonce)
	}
	return sendUDP(ctx, dial, p.Nonce)
}

type dialFunc func(ctx context.Context, network string) (net.Conn, error)

func sendTCP(ctx context.Context, dial dialFunc, nonce string) (any, *protocol.Error) {
	start := time.Now()
	c, err := dial(ctx, "tcp")
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		if pe := policyError(err); pe != nil {
			return nil, pe
		}
		return protocol.PathSendResult{Outcome: dialOutcome(err, ctx), RemoteIP: opRemoteIP(err), Detail: errDetail(err),
			ConnectMS: elapsed}, nil
	}
	defer c.Close()
	res := protocol.PathSendResult{Outcome: "connected", LocalAddr: addrString(c.LocalAddr()), RemoteIP: hostOf(c.RemoteAddr()),
		ConnectMS: elapsed}
	c.SetWriteDeadline(deadlineOr(ctx, time.Now().Add(2*time.Second)))
	if _, err := c.Write([]byte(protocol.PathTestPayload(nonce) + "\n")); err != nil {
		res.Detail = "connected, but sending the nonce failed: " + errDetail(err)
	}
	return res, nil
}

func sendUDP(ctx context.Context, dial dialFunc, nonce string) (any, *protocol.Error) {
	start := time.Now()
	c, err := dial(ctx, "udp")
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		if pe := policyError(err); pe != nil {
			return nil, pe
		}
		return protocol.PathSendResult{Outcome: dialOutcome(err, ctx), RemoteIP: opRemoteIP(err), Detail: errDetail(err),
			ConnectMS: elapsed}, nil
	}
	defer c.Close()
	res := protocol.PathSendResult{Outcome: "sent", LocalAddr: addrString(c.LocalAddr()), RemoteIP: hostOf(c.RemoteAddr()),
		ConnectMS: elapsed}
	payload := []byte(protocol.PathTestPayload(nonce))
	buf := make([]byte, 64)
	for i := 0; i < udpSends; i++ {
		if _, err := c.Write(payload); err != nil {
			return udpFailure(res, err), nil
		}
		// An ICMP port unreachable for a connected UDP socket surfaces on the next call, so read briefly after every
		// send, including the last. The receiver never answers, so a reply is not expected either way.
		c.SetReadDeadline(deadlineOr(ctx, time.Now().Add(udpInterval)))
		if _, err := c.Read(buf); err != nil && !isTimeout(err) {
			return udpFailure(res, err), nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return res, nil
}

func udpFailure(res protocol.PathSendResult, err error) protocol.PathSendResult {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		res.Outcome = "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		res.Outcome = "unreachable"
	default:
		res.Outcome = "error"
	}
	res.Detail = errDetail(err)
	return res
}

// policyError returns the policy's own error (denied, unresolved, invalid) so the hub reports it as such and never as a
// blocked path.
func policyError(err error) *protocol.Error {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

// dialOutcome maps a connect failure to the outcomes path_test reports.
func dialOutcome(err error, ctx context.Context) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		isTimeout(err), ctx != nil && ctx.Err() != nil:
		return "timeout"
	}
	return "error"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func opRemoteIP(err error) string {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Addr != nil {
		return hostOf(oe.Addr)
	}
	return ""
}

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap().String()
	}
	return a.String()
}

func errDetail(err error) string {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

func deadlineOr(ctx context.Context, t time.Time) time.Time {
	if d, ok := ctx.Deadline(); ok && d.Before(t) {
		return d
	}
	return t
}

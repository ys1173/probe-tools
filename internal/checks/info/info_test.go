package info

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

func TestParseRoute4(t *testing.T) {
	in := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	010011AC	0003	0	0	0	00000000	0	0	0
eth0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
eth1	00000000	00000000	0001	0	0	0	00000000	0	0	0
`
	got := parseRoute4(strings.NewReader(in))
	want := []Gateway{{Interface: "eth0", Gateway: "172.17.0.1", Family: "4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseRoute6(t *testing.T) {
	in := `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`
	got := parseRoute6(strings.NewReader(in))
	want := []Gateway{{Interface: "eth0", Gateway: "fe80::1", Family: "6"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseResolvConf(t *testing.T) {
	in := "# comment\nsearch example.com\nnameserver 10.0.0.2\nnameserver  2001:db8::53 \n; x\nnameserver bogus\noptions ndots:1\n"
	got := parseResolvConf(strings.NewReader(in))
	want := []string{"10.0.0.2", "2001:db8::53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestProbeInfo(t *testing.T) {
	p, err := policy.New(policy.Config{Mode: policy.ModeOpen})
	if err != nil {
		t.Fatal(err)
	}
	r := check.NewRegistry()
	Register(r)
	f, _ := r.Get(protocol.CheckProbeInfo)
	env := &check.Env{Policy: p, ProbeName: "p1", Site: "s1", Version: "v9", ListenPortMin: 40000, ListenPortMax: 40010,
		Capabilities: map[string]bool{"raw_icmp": true}}
	res, perr := f(context.Background(), env, nil)
	if perr != nil {
		t.Fatal(perr)
	}
	r1 := res.(Result)
	if r1.Name != "p1" || r1.Site != "s1" || r1.Version != "v9" || r1.ListenPorts != "40000-40010" || r1.Policy.Mode != "open" ||
		!r1.Capabilities["raw_icmp"] || len(r1.Interfaces) == 0 || r1.Hostname == "" {
		t.Fatalf("unexpected result %+v", r1)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatal(err)
	}
	if _, perr := f(context.Background(), env, json.RawMessage(`{"x":1}`)); perr == nil || perr.Code != protocol.CodeInvalidParams {
		t.Fatalf("unknown param accepted: %v", perr)
	}
	env.ListenPortMin, env.ListenPortMax = 0, 0
	res, _ = f(context.Background(), env, nil)
	if res.(Result).ListenPorts != "" {
		t.Fatal("listen_ports should be empty when listening is off")
	}
}

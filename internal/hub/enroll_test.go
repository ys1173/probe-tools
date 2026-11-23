package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"probetools/internal/protocol"
)

func postEnroll(t *testing.T, base, token string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(protocol.EnrollRequest{Token: token, Hostname: "box", Version: "test"})
	resp, err := http.Post(base+protocol.PathEnroll, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEnrollEndpoint(t *testing.T) {
	e := newEnv(t, Options{})
	ctx := context.Background()
	tok, _ := e.store.CreateToken(ctx, "edge-1", "syd", time.Hour, false)

	resp := postEnroll(t, e.srv.URL, tok.Value)
	var out protocol.EnrollResponse
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || out.Name != "edge-1" || out.Site != "syd" || out.ProbeID == "" || out.Secret == "" {
		t.Fatalf("%d %+v", resp.StatusCode, out)
	}
	// The new identity works on the link.
	e.connect(out, true)

	// Every refusal looks the same to the caller.
	expired, _ := e.store.CreateToken(ctx, "edge-2", "syd", time.Nanosecond, false)
	revoked, _ := e.store.CreateToken(ctx, "edge-3", "syd", time.Hour, false)
	e.store.RevokeToken(ctx, revoked.ID)
	clash, _ := e.store.CreateToken(ctx, "edge-4", "syd", time.Hour, false)
	e.enroll("edge-4", "syd")
	time.Sleep(time.Millisecond)

	var bodies []string
	for _, v := range []string{tok.Value, "garbage", expired.Value, revoked.Value, clash.Value, ""} {
		resp := postEnroll(t, e.srv.URL, v)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d", v, resp.StatusCode)
		}
		bodies = append(bodies, string(b))
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("refusals differ: %q vs %q", b, bodies[0])
		}
	}
	logs := e.logs.String()
	for _, reason := range []string{ReasonTokenUsed, ReasonTokenUnknown, ReasonTokenExpired, ReasonTokenRevoked, ReasonNameTaken} {
		if !strings.Contains(logs, `"reason":"`+reason+`"`) {
			t.Errorf("reason %s not logged", reason)
		}
	}
	for _, secret := range []string{tok.Value, expired.Value, revoked.Value, clash.Value, out.Secret} {
		if strings.Contains(logs, secret) {
			t.Fatal("token or secret logged")
		}
	}

	// Malformed and oversized bodies get the same 401.
	for _, body := range []string{"{", `{"token":"` + strings.Repeat("a", 5000) + `"}`} {
		resp, err := http.Post(e.srv.URL+protocol.PathEnroll, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("body %.10q: %d", body, resp.StatusCode)
		}
	}
	// Only POST.
	resp, _ = http.Get(e.srv.URL + protocol.PathEnroll)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET enroll: %d", resp.StatusCode)
	}
}

func TestEnrollRateLimit(t *testing.T) {
	e := newEnv(t, Options{EnrollRate: rate.Every(time.Hour), EnrollBurst: 3})
	codes := []int{}
	for range 5 {
		resp := postEnroll(t, e.srv.URL, "guess")
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	want := []int{401, 401, 401, 429, 429}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("codes %v, want %v", codes, want)
		}
	}
}

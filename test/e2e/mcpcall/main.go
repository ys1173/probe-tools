// Command mcpcall is the e2e test's MCP client. It connects to the hub over streamable HTTP with a bearer token and
// either lists the tools or calls one, printing a single JSON object on stdout:
//
//	mcpcall --url URL --token T --list
//	  {"tools":[{"name":..,"read_only":true,..}],"elapsed_ms":N}
//	mcpcall --url URL --token T --tool ping --args '{"probes":["*"],"target":"10.0.0.1"}'
//	  {"is_error":false,"structured":{..},"text":"..","elapsed_ms":N}
//	mcpcall --url URL --raw-status [--token T]
//	  {"status":401,"www_authenticate":".."}   (one initialize POST, no SDK; token "" sends no Authorization)
//
// A transport or protocol failure prints {"transport_error":"..","elapsed_ms":N} and exits 0, so the test script can
// assert on it with jq like any other outcome.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(r)
}

func main() {
	url := flag.String("url", "", "MCP endpoint")
	token := flag.String("token", "", "bearer token")
	tool := flag.String("tool", "", "tool to call")
	args := flag.String("args", "{}", "tool arguments as a JSON object")
	list := flag.Bool("list", false, "list tools")
	raw := flag.Bool("raw-status", false, "send one initialize POST and print the HTTP status")
	timeout := flag.Duration("timeout", 70*time.Second, "overall timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	start := time.Now()
	out := map[string]any{}
	defer func() {
		out["elapsed_ms"] = time.Since(start).Milliseconds()
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	}()

	if *raw {
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-raw","version":"1"}}}`)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, *url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			out["transport_error"] = err.Error()
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		out["status"] = resp.StatusCode
		out["www_authenticate"] = resp.Header.Get("WWW-Authenticate")
		out["body"] = string(b)
		return
	}

	hc := &http.Client{Transport: bearer{token: *token, base: http.DefaultTransport}}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-mcpcall", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: *url, HTTPClient: hc,
		DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		out["transport_error"] = err.Error()
		return
	}
	defer sess.Close()

	if *list {
		res, err := sess.ListTools(ctx, nil)
		if err != nil {
			out["transport_error"] = err.Error()
			return
		}
		tools := []map[string]any{}
		for _, t := range res.Tools {
			m := map[string]any{"name": t.Name, "description": t.Description}
			if t.Annotations != nil {
				m["read_only"] = t.Annotations.ReadOnlyHint
				m["annotations"] = t.Annotations
			} else {
				m["read_only"] = false
			}
			m["input_schema"] = t.InputSchema
			tools = append(tools, m)
		}
		out["tools"] = tools
		return
	}

	if *tool == "" {
		fmt.Fprintln(os.Stderr, "need --tool or --list")
		os.Exit(2)
	}
	var a map[string]any
	if err := json.Unmarshal([]byte(*args), &a); err != nil {
		fmt.Fprintln(os.Stderr, "--args is not a JSON object:", err)
		os.Exit(2)
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: *tool, Arguments: a})
	if err != nil {
		out["transport_error"] = err.Error()
		return
	}
	out["is_error"] = res.IsError
	out["structured"] = res.StructuredContent
	text := ""
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			text += t.Text
		}
	}
	out["text"] = text
}

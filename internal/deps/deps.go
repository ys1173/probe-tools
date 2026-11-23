//go:build tools

// Package deps pins the project's third-party modules in go.mod before every package imports them. Builds never
// include it.
package deps

import (
	_ "github.com/coder/websocket"
	_ "github.com/google/jsonschema-go/jsonschema"
	_ "github.com/miekg/dns"
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
	_ "golang.org/x/net/icmp"
	_ "golang.org/x/net/ipv4"
	_ "golang.org/x/net/ipv6"
	_ "golang.org/x/time/rate"
	_ "gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

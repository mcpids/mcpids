package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mcpids/mcpids/internal/mcp"
)

// serveSSE proxies a GET (SSE or long-poll) request from the client to the upstream.
// Each SSE event is parsed and passed through the outbound pipeline before being
// forwarded to the client. Events that the pipeline blocks are silently dropped.
func (p *Proxy) serveSSE(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := SessionFromContext(ctx)
	serverID := ServerIDFromContext(ctx)
	if sess == nil {
		http.Error(w, "session not initialised", http.StatusInternalServerError)
		return
	}

	// Build the upstream request.
	upstreamURL := *p.upstream
	upstreamURL.Path = r.URL.Path
	upstreamURL.RawQuery = r.URL.RawQuery

	upReq, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusBadGateway)
		return
	}
	copyHeaders(upReq.Header, r.Header)

	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	// Relay response headers to the client.
	for k, vv := range upResp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(upResp.StatusCode)

	flusher, canFlush := w.(http.Flusher)

	// Read the SSE stream line by line.
	// SSE events are separated by blank lines; each event may have multiple
	// field lines. We collect "data:" payloads, then dispatch at the blank line.
	scanner := bufio.NewScanner(upResp.Body)
	scanner.Buffer(make([]byte, p.maxSize), p.maxSize)

	var eventLines []string // accumulated data payloads for the current event

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Blank line = end of SSE event.
			if len(eventLines) > 0 {
				payload := strings.Join(eventLines, "")
				filtered := p.filterSSEPayload(ctx, payload, sess, serverID)
				if filtered != "" {
					fmt.Fprintf(w, "data: %s\n\n", filtered)
					if canFlush {
						flusher.Flush()
					}
				}
				eventLines = eventLines[:0]
			} else {
				// Keep-alive blank event.
				fmt.Fprintln(w)
				if canFlush {
					flusher.Flush()
				}
			}
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			eventLines = append(eventLines, strings.TrimPrefix(line, "data: "))
		} else {
			// Pass through non-data SSE fields (id:, event:, retry:, comments).
			fmt.Fprintln(w, line)
			if canFlush {
				flusher.Flush()
			}
		}
	}
}

// filterSSEPayload runs the outbound pipeline on a single SSE data payload.
// Returns the (possibly modified) payload bytes, or "" to suppress the event.
func (p *Proxy) filterSSEPayload(ctx context.Context, payload string, sess *mcp.Session, serverID string) string {
	msg, err := p.parser.ParseMessage([]byte(payload))
	if err != nil {
		// Not a valid JSON-RPC message; pass through unchanged.
		return payload
	}

	// Determine method: present on requests/notifications, absent on responses.
	method := msg.Method
	if method == "" {
		// Look up in-flight method for this response ID.
		if v, ok := p.inflight.Load(string(msg.ID)); ok {
			method, _ = v.(string)
		}
	}
	// Fallback: infer from result shape.
	if method == "" && msg.Result != nil {
		method = detectResponseMethod(msg.Result)
	}

	result := p.pipeline.Run(ctx, &InterceptRequest{
		Message:   msg,
		Method:    method,
		Direction: mcp.DirectionOutbound,
		Session:   sess,
		ServerID:  serverID,
	})

	if result.Blocked {
		return "" // suppress the event
	}
	if result.ModifiedBody != nil {
		return string(result.ModifiedBody)
	}
	return payload
}

// detectResponseMethod infers the MCP method from a JSON-RPC result shape.
func detectResponseMethod(result json.RawMessage) string {
	var toolsProbe struct {
		Tools *json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(result, &toolsProbe) == nil && toolsProbe.Tools != nil {
		return mcp.MethodToolsList
	}

	var callProbe struct {
		Content *json.RawMessage `json:"content"`
	}
	if json.Unmarshal(result, &callProbe) == nil && callProbe.Content != nil {
		return mcp.MethodToolsCall
	}

	var initProbe struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(result, &initProbe) == nil && initProbe.ProtocolVersion != "" {
		return mcp.MethodInitialize
	}

	return ""
}

// copyHeaders copies HTTP headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

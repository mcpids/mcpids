package gateway

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/mcpids/mcpids/internal/mcp"
)

// proxyMeta is stored in the request context so that ModifyResponse can access
// the session and method information resolved during request processing.
type proxyMeta struct {
	sess     *mcp.Session
	serverID string
	method   string
	msgID    string
}

// Proxy is an HTTP reverse proxy that intercepts MCP JSON-RPC traffic.
// For POST requests it buffers the full body for inspection.
// For GET (SSE) requests it delegates to serveSSE for streaming interception.
type Proxy struct {
	upstream *url.URL
	pipeline *Pipeline
	parser   *mcp.Parser
	maxSize  int
	// inflight tracks requestID → method for outbound response routing.
	inflight sync.Map
	rp       *httputil.ReverseProxy
}

// NewProxy creates a Proxy that forwards requests to upstream.
func NewProxy(upstream *url.URL, pipeline *Pipeline, maxMessageSize int) *Proxy {
	if maxMessageSize <= 0 {
		maxMessageSize = mcp.DefaultMaxMessageSize
	}
	p := &Proxy{
		upstream: upstream,
		pipeline: pipeline,
		parser:   mcp.NewParser(maxMessageSize),
		maxSize:  maxMessageSize,
	}

	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
		},
		ModifyResponse: p.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("proxy: upstream error", "error", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}

	return p
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		p.serveSSE(w, r)
		return
	}

	sess := SessionFromContext(r.Context())
	serverID := ServerIDFromContext(r.Context())
	if sess == nil {
		http.Error(w, "session not initialised", http.StatusInternalServerError)
		return
	}

	// Buffer request body (up to maxSize + 1 to detect oversize).
	maxSize := int64(p.maxSize) + 1
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	r.Body.Close()
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if len(bodyBytes) > p.maxSize {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Parse the JSON-RPC envelope.
	msg, err := p.parser.ParseMessage(bodyBytes)
	if err != nil {
		slog.Warn("proxy: request parse error; forwarding as-is", "error", err)
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		p.rp.ServeHTTP(w, r)
		return
	}

	// Track in-flight method for response routing.
	msgID := string(msg.ID)
	if msg.Method != "" && msgID != "" {
		p.inflight.Store(msgID, msg.Method)
	}

	// Run inbound pipeline.
	result := p.pipeline.Run(r.Context(), &InterceptRequest{
		Message:   msg,
		Method:    msg.Method,
		Direction: mcp.DirectionInbound,
		Session:   sess,
		ServerID:  serverID,
	})

	if result.Blocked {
		p.inflight.Delete(msgID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // JSON-RPC errors use HTTP 200
		_, _ = w.Write(result.ModifiedBody)
		return
	}

	// Inject meta into context so ModifyResponse can access it.
	ctx := context.WithValue(r.Context(), contextKeyProxyMeta, &proxyMeta{
		sess:     sess,
		serverID: serverID,
		method:   msg.Method,
		msgID:    msgID,
	})

	// Restore the body for forwarding.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	p.rp.ServeHTTP(w, r.WithContext(ctx))
}

// modifyResponse intercepts the upstream JSON response for outbound pipeline processing.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	meta, _ := resp.Request.Context().Value(contextKeyProxyMeta).(*proxyMeta)
	if meta == nil {
		return nil
	}
	defer p.inflight.Delete(meta.msgID)

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return nil
	}

	// Buffer the response body.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(p.maxSize)+1))
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return nil
	}

	msg, err := p.parser.ParseMessage(bodyBytes)
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	// Determine method from in-flight map if not already known.
	method := meta.method
	if method == "" {
		if v, ok := p.inflight.Load(string(msg.ID)); ok {
			method, _ = v.(string)
		}
	}

	result := p.pipeline.Run(resp.Request.Context(), &InterceptRequest{
		Message:   msg,
		Method:    method,
		Direction: mcp.DirectionOutbound,
		Session:   meta.sess,
		ServerID:  meta.serverID,
	})

	var responseBody []byte
	if result.ModifiedBody != nil {
		responseBody = result.ModifiedBody
	} else {
		responseBody = bodyBytes
	}

	resp.Body = io.NopCloser(bytes.NewReader(responseBody))
	resp.ContentLength = int64(len(responseBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(responseBody)))
	return nil
}

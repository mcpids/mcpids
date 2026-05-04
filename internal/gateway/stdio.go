package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"

	"github.com/mcpids/mcpids/internal/mcp"
)

// StdioProxy wraps a subprocess MCP server, intercepting its stdin and stdout.
// The subprocess is started with the provided command and arguments.
// All MCP JSON-RPC messages on the pipe are inspected by the pipeline.
type StdioProxy struct {
	cmd      []string
	pipeline *Pipeline
	parser   *mcp.Parser
	sess     *mcp.Session
	serverID string
	maxSize  int
}

// NewStdioProxy creates a StdioProxy for the given subprocess command.
func NewStdioProxy(cmd []string, pipeline *Pipeline, sess *mcp.Session, serverID string, maxMessageSize int) *StdioProxy {
	if maxMessageSize <= 0 {
		maxMessageSize = mcp.DefaultMaxMessageSize
	}
	return &StdioProxy{
		cmd:      cmd,
		pipeline: pipeline,
		parser:   mcp.NewParser(maxMessageSize),
		sess:     sess,
		serverID: serverID,
		maxSize:  maxMessageSize,
	}
}

// Run starts the subprocess and proxies stdin/stdout until the process exits
// or the context is cancelled.
func (s *StdioProxy) Run(ctx context.Context) error {
	if len(s.cmd) == 0 {
		return fmt.Errorf("stdio: empty command")
	}

	cmd := exec.CommandContext(ctx, s.cmd[0], s.cmd[1:]...)
	cmd.Stderr = os.Stderr

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdio: stdin pipe: %w", err)
	}

	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdio: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("stdio: start process: %w", err)
	}
	slog.Info("stdio: subprocess started", "pid", cmd.Process.Pid, "cmd", s.cmd[0])

	// done is closed when either goroutine exits.
	done := make(chan struct{}, 2)

	// client stdin → upstream stdin (inbound inspection)
	go func() {
		s.pipeInbound(ctx, os.Stdin, upstreamIn)
		done <- struct{}{}
	}()

	// upstream stdout → client stdout (outbound inspection)
	go func() {
		s.pipeOutbound(ctx, upstreamOut, os.Stdout)
		done <- struct{}{}
	}()

	// Wait for one pipe to close, then clean up.
	select {
	case <-done:
	case <-ctx.Done():
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	slog.Info("stdio: subprocess exited")
	return nil
}

// pipeInbound reads newline-delimited JSON-RPC messages from src (client stdin),
// runs each through the inbound pipeline, and writes allowed messages to dst (upstream stdin).
// Blocked messages cause an error response to be written to os.Stdout (the client's view).
func (s *StdioProxy) pipeInbound(ctx context.Context, src io.Reader, dst io.WriteCloser) {
	defer dst.Close()

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, s.maxSize), s.maxSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		msg, err := s.parser.ParseMessage(line)
		if err != nil {
			// Not a valid JSON-RPC message; forward as-is.
			fmt.Fprintf(dst, "%s\n", line)
			continue
		}

		result := s.pipeline.Run(ctx, &InterceptRequest{
			Message:   msg,
			Method:    msg.Method,
			Direction: mcp.DirectionInbound,
			Session:   s.sess,
			ServerID:  s.serverID,
		})

		if result.Blocked {
			// Write the error response to the client's stdout.
			if result.ModifiedBody != nil {
				fmt.Fprintf(os.Stdout, "%s\n", result.ModifiedBody)
			}
			continue
		}

		// Forward to upstream.
		fmt.Fprintf(dst, "%s\n", line)
	}
}

// pipeOutbound reads newline-delimited JSON-RPC messages from src (upstream stdout),
// runs each through the outbound pipeline, and writes allowed (or modified) messages to dst.
func (s *StdioProxy) pipeOutbound(ctx context.Context, src io.Reader, dst io.Writer) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, s.maxSize), s.maxSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		msg, err := s.parser.ParseMessage(line)
		if err != nil {
			fmt.Fprintf(dst, "%s\n", line)
			continue
		}

		result := s.pipeline.Run(ctx, &InterceptRequest{
			Message:   msg,
			Method:    msg.Method,
			Direction: mcp.DirectionOutbound,
			Session:   s.sess,
			ServerID:  s.serverID,
		})

		if result.Blocked {
			// Write error response to client, not the original upstream message.
			if result.ModifiedBody != nil {
				fmt.Fprintf(dst, "%s\n", result.ModifiedBody)
			}
			continue
		}

		if result.ModifiedBody != nil {
			fmt.Fprintf(dst, "%s\n", result.ModifiedBody)
		} else {
			fmt.Fprintf(dst, "%s\n", line)
		}
	}
}

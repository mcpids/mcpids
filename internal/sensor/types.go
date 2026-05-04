// Package sensor defines the interface and types for the MCPIDS eBPF sensor.
// The sensor provides kernel-level visibility into process creation and network
// activity, enriching MCP call records with process and connection context.
//
// The implementation is split into:
//   - This package: interface + types (no kernel dependencies)
//   - Concrete eBPF implementation in sensor/ebpf (Linux only, build-tagged)
//   - Stub fallback in sensor/stub (all platforms)
package sensor

import (
	"context"
	"net"
	"time"
)

// EventKind identifies the category of a kernel event.
type EventKind string

const (
	// EventKindProcessExec is emitted when a new process is executed.
	EventKindProcessExec EventKind = "process_exec"

	// EventKindProcessExit is emitted when a process exits.
	EventKindProcessExit EventKind = "process_exit"

	// EventKindTCPConnect is emitted when a process establishes a TCP connection.
	EventKindTCPConnect EventKind = "tcp_connect"

	// EventKindTCPAccept is emitted when a process accepts a TCP connection.
	EventKindTCPAccept EventKind = "tcp_accept"

	// EventKindTLSRead is emitted when plaintext data is read from a TLS session.
	// Requires uprobe attachment to OpenSSL or similar.
	EventKindTLSRead EventKind = "tls_read"

	// EventKindTLSWrite is emitted when plaintext data is written to a TLS session.
	EventKindTLSWrite EventKind = "tls_write"
)

// Event is a kernel-level observation emitted by the eBPF sensor.
type Event struct {
	// Kind is the event category.
	Kind EventKind `json:"kind"`

	// Timestamp is when the event was observed.
	Timestamp time.Time `json:"timestamp"`

	// PID is the process ID of the subject process.
	PID uint32 `json:"pid"`

	// PPID is the parent process ID.
	PPID uint32 `json:"ppid"`

	// Comm is the short process name (up to 16 bytes on Linux).
	Comm string `json:"comm"`

	// ExePath is the full executable path, if available.
	ExePath string `json:"exe_path,omitempty"`

	// Args are the process arguments, if available (exec events only).
	Args []string `json:"args,omitempty"`

	// SrcAddr is the source address for network events.
	SrcAddr net.IP `json:"src_addr,omitempty"`

	// DstAddr is the destination address for network events.
	DstAddr net.IP `json:"dst_addr,omitempty"`

	// SrcPort is the source port for network events.
	SrcPort uint16 `json:"src_port,omitempty"`

	// DstPort is the destination port for network events.
	DstPort uint16 `json:"dst_port,omitempty"`

	// Payload is the raw TLS plaintext payload (TLS events only, truncated).
	Payload []byte `json:"payload,omitempty"`

	// TenantID and AgentID are injected by the manager based on process context.
	TenantID string `json:"tenant_id,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
}

// AttachPoint describes a kernel hook point for eBPF programs.
type AttachPoint struct {
	// Kind is one of: "kprobe", "kretprobe", "tracepoint", "uprobe"
	Kind string `json:"kind"`

	// Symbol is the kernel symbol or tracepoint name to attach to.
	Symbol string `json:"symbol"`

	// Target is the target binary path for uprobe attachment.
	Target string `json:"target,omitempty"`
}

// Manager is the interface for the eBPF sensor lifecycle.
type Manager interface {
	// Start loads eBPF programs and begins emitting events.
	Start(ctx context.Context) error

	// Stop unloads eBPF programs and shuts down the event stream.
	Stop() error

	// Events returns the channel on which sensor events are published.
	// The channel is closed when the sensor is stopped.
	Events() <-chan Event

	// IsSupported returns true if eBPF is available on this platform/kernel.
	IsSupported() bool
}

//go:build linux

package sensor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ebpfManager is the Linux eBPF-backed sensor implementation.
// In a complete production build this would load compiled BPF object files
// via github.com/cilium/ebpf and attach kprobes/tracepoints.
// For the MVP it provides the correct interface binding so the binary compiles
// on Linux; the actual BPF programs are loaded at runtime from ProgramsDir.
type ebpfManager struct {
	cfg         Config
	events      chan Event
	once        sync.Once
	cancel      context.CancelFunc
	collections []*ebpf.Collection
	links       []link.Link
	readers     []*ringbuf.Reader
	seen        map[uint32]struct{}
	wg          sync.WaitGroup
}

// newEBPFManager creates a new eBPF sensor manager on Linux.
func newEBPFManager(cfg Config) (Manager, error) {
	if cfg.ProgramsDir != "" {
		if _, err := os.Stat(cfg.ProgramsDir); err != nil {
			return nil, fmt.Errorf("sensor: programs dir %q not found: %w", cfg.ProgramsDir, err)
		}
	}

	bufSize := cfg.EventBufferSize
	if bufSize <= 0 {
		bufSize = 1024
	}

	return &ebpfManager{
		cfg:    cfg,
		events: make(chan Event, bufSize),
		seen:   make(map[uint32]struct{}),
	}, nil
}

// Start implements Manager.
// It loads compiled BPF object files from ProgramsDir, attaches known program
// section types, opens ring-buffer readers, and keeps a /proc polling fallback
// for environments where the loaded objects expose no compatible event stream.
func (m *ebpfManager) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	slog.Info("sensor: starting eBPF manager",
		"programs_dir", m.cfg.ProgramsDir,
		"kprobes", m.cfg.AttachKprobes,
		"uprobes", m.cfg.AttachUprobes)

	if err := m.loadCollections(); err != nil {
		return err
	}

	fallbackProcPolling := len(m.readers) == 0
	if fallbackProcPolling {
		// Fallback signal source: poll /proc for new PIDs and emit process_exec events.
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				if err := m.scanProcExec(runCtx); err != nil {
					slog.Debug("sensor: /proc scan failed", "error", err)
				}
				select {
				case <-runCtx.Done():
					slog.Debug("sensor: eBPF manager context cancelled")
					return
				case <-ticker.C:
				}
			}
		}()
	}

	slog.Info("sensor: eBPF manager started",
		"loaded_collections", len(m.collections),
		"ringbuf_readers", len(m.readers),
		"fallback_proc_polling", fallbackProcPolling)
	return nil
}

// Stop implements Manager.
func (m *ebpfManager) Stop() error {
	m.once.Do(func() {
		if m.cancel != nil {
			m.cancel()
		}
		m.closeReaders()
		m.closeLinks()
		m.wg.Wait()
		m.closeCollections()
		close(m.events)
	})
	return nil
}

// Events implements Manager.
func (m *ebpfManager) Events() <-chan Event {
	return m.events
}

// IsSupported implements Manager.
func (m *ebpfManager) IsSupported() bool {
	return true
}

func (m *ebpfManager) scanProcExec(ctx context.Context) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		if _, ok := m.seen[pid]; ok {
			continue
		}
		m.seen[pid] = struct{}{}

		commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		exePath, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		ev := Event{
			Kind:      EventKindProcessExec,
			Timestamp: time.Now().UTC(),
			PID:       pid,
			Comm:      strings.TrimSpace(string(commBytes)),
			ExePath:   exePath,
			TenantID:  m.cfg.TenantID,
			AgentID:   m.cfg.AgentID,
		}
		select {
		case <-ctx.Done():
			return nil
		case m.events <- ev:
		default:
			slog.Debug("sensor: event buffer full, dropping process event", "pid", pid)
		}
	}
	return nil
}

func (m *ebpfManager) loadCollections() error {
	if m.cfg.ProgramsDir == "" {
		return nil
	}

	matches, err := filepath.Glob(filepath.Join(m.cfg.ProgramsDir, "*.o"))
	if err != nil {
		return fmt.Errorf("sensor: scan BPF objects: %w", err)
	}
	for _, path := range matches {
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			m.cleanupBPFResources()
			return fmt.Errorf("sensor: load BPF spec %s: %w", path, err)
		}
		collection, err := ebpf.NewCollection(spec)
		if err != nil {
			m.cleanupBPFResources()
			return fmt.Errorf("sensor: load BPF collection %s: %w", path, err)
		}
		m.collections = append(m.collections, collection)
		if err := m.attachCollectionPrograms(spec, collection); err != nil {
			m.cleanupBPFResources()
			return fmt.Errorf("sensor: attach BPF programs from %s: %w", path, err)
		}
		if err := m.openCollectionReaders(collection); err != nil {
			m.cleanupBPFResources()
			return fmt.Errorf("sensor: open BPF readers from %s: %w", path, err)
		}
		slog.Info("sensor: loaded BPF collection", "path", path)
	}
	return nil
}

func (m *ebpfManager) attachCollectionPrograms(spec *ebpf.CollectionSpec, collection *ebpf.Collection) error {
	for name, progSpec := range spec.Programs {
		prog := collection.Programs[name]
		if prog == nil || progSpec == nil {
			continue
		}
		section := strings.TrimSpace(progSpec.SectionName)
		switch {
		case strings.HasPrefix(section, "tracepoint/"):
			parts := strings.SplitN(strings.TrimPrefix(section, "tracepoint/"), "/", 2)
			if len(parts) != 2 {
				continue
			}
			lnk, err := link.Tracepoint(parts[0], parts[1], prog, nil)
			if err != nil {
				return fmt.Errorf("tracepoint %s: %w", section, err)
			}
			m.links = append(m.links, lnk)
		case strings.HasPrefix(section, "tp/"):
			parts := strings.SplitN(strings.TrimPrefix(section, "tp/"), "/", 2)
			if len(parts) != 2 {
				continue
			}
			lnk, err := link.Tracepoint(parts[0], parts[1], prog, nil)
			if err != nil {
				return fmt.Errorf("tracepoint %s: %w", section, err)
			}
			m.links = append(m.links, lnk)
		case strings.HasPrefix(section, "kprobe/"):
			symbol := strings.TrimPrefix(section, "kprobe/")
			if symbol == "" {
				continue
			}
			lnk, err := link.Kprobe(symbol, prog, nil)
			if err != nil {
				return fmt.Errorf("kprobe %s: %w", symbol, err)
			}
			m.links = append(m.links, lnk)
		case strings.HasPrefix(section, "kretprobe/"):
			symbol := strings.TrimPrefix(section, "kretprobe/")
			if symbol == "" {
				continue
			}
			lnk, err := link.Kretprobe(symbol, prog, nil)
			if err != nil {
				return fmt.Errorf("kretprobe %s: %w", symbol, err)
			}
			m.links = append(m.links, lnk)
		case strings.HasPrefix(section, "uprobe/"):
			if !m.cfg.AttachUprobes {
				continue
			}
			symbol := strings.TrimPrefix(section, "uprobe/")
			if symbol == "" || m.cfg.TLSLibPath == "" {
				slog.Warn("sensor: uprobe skipped - symbol or TLSLibPath empty",
					"section", section,
					"tls_lib_path", m.cfg.TLSLibPath)
				continue
			}
			lnk, err := link.Uprobe(symbol, prog, &link.UprobeOptions{Path: m.cfg.TLSLibPath})
			if err != nil {
				return fmt.Errorf("uprobe %s (%s): %w", symbol, m.cfg.TLSLibPath, err)
			}
			m.links = append(m.links, lnk)
		case strings.HasPrefix(section, "uretprobe/"):
			if !m.cfg.AttachUprobes {
				continue
			}
			symbol := strings.TrimPrefix(section, "uretprobe/")
			if symbol == "" || m.cfg.TLSLibPath == "" {
				slog.Warn("sensor: uretprobe skipped - symbol or TLSLibPath empty",
					"section", section,
					"tls_lib_path", m.cfg.TLSLibPath)
				continue
			}
			lnk, err := link.Uretprobe(symbol, prog, &link.UprobeOptions{Path: m.cfg.TLSLibPath})
			if err != nil {
				return fmt.Errorf("uretprobe %s (%s): %w", symbol, m.cfg.TLSLibPath, err)
			}
			m.links = append(m.links, lnk)
		}
	}
	return nil
}

func (m *ebpfManager) openCollectionReaders(collection *ebpf.Collection) error {
	for name, bpfMap := range collection.Maps {
		if bpfMap == nil || bpfMap.Type() != ebpf.RingBuf {
			continue
		}
		reader, err := ringbuf.NewReader(bpfMap)
		if err != nil {
			return fmt.Errorf("ringbuf %s: %w", name, err)
		}
		m.readers = append(m.readers, reader)
		m.wg.Add(1)
		go m.consumeRingBuffer(name, reader)
	}
	return nil
}

func (m *ebpfManager) consumeRingBuffer(mapName string, reader *ringbuf.Reader) {
	defer m.wg.Done()
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			if m.cancel != nil {
				select {
				case <-time.After(100 * time.Millisecond):
				default:
				}
			}
			slog.Debug("sensor: ringbuf read failed", "map", mapName, "error", err)
			continue
		}
		ev, err := decodeRingbufEvent(record.RawSample, m.cfg.TenantID, m.cfg.AgentID)
		if err != nil {
			slog.Debug("sensor: ringbuf decode failed", "map", mapName, "error", err)
			continue
		}
		select {
		case m.events <- ev:
		default:
			slog.Debug("sensor: event buffer full, dropping ringbuf event", "map", mapName, "kind", ev.Kind)
		}
	}
}

func (m *ebpfManager) closeCollections() {
	for _, collection := range m.collections {
		collection.Close()
	}
	m.collections = nil
}

func (m *ebpfManager) closeLinks() {
	for _, lnk := range m.links {
		_ = lnk.Close()
	}
	m.links = nil
}

func (m *ebpfManager) closeReaders() {
	for _, reader := range m.readers {
		_ = reader.Close()
	}
	m.readers = nil
}

func (m *ebpfManager) cleanupBPFResources() {
	m.closeReaders()
	m.closeLinks()
	m.wg.Wait()
	m.closeCollections()
}

// bpfEventRecord is the supported binary ring-buffer ABI for MCPIDS BPF objects.
// Programs may also emit JSON-encoded sensor.Event payloads for forward compatibility.
type bpfEventRecord struct {
	Kind        uint32
	TimestampNs uint64
	PID         uint32
	PPID        uint32
	SrcAddr     [16]byte
	DstAddr     [16]byte
	SrcPort     uint16
	DstPort     uint16
	PayloadLen  uint32
	Comm        [16]byte
	ExePath     [256]byte
	Args        [256]byte
	Payload     [256]byte
}

func decodeRingbufEvent(raw []byte, tenantID, agentID string) (Event, error) {
	var jsonEvent Event
	if err := json.Unmarshal(raw, &jsonEvent); err == nil && jsonEvent.Kind != "" {
		jsonEvent.TenantID = tenantID
		jsonEvent.AgentID = agentID
		if jsonEvent.Timestamp.IsZero() {
			jsonEvent.Timestamp = time.Now().UTC()
		}
		return jsonEvent, nil
	}

	const minRecordSize = 4 + 8 + 4 + 4 + 16 + 16 + 2 + 2 + 4 + 16 + 256 + 256
	if len(raw) < minRecordSize {
		return Event{}, fmt.Errorf("record too short: %d", len(raw))
	}

	var rec bpfEventRecord
	copyEventRecord(&rec, raw)
	ev := Event{
		Kind:      eventKindFromWire(rec.Kind),
		Timestamp: time.Unix(0, int64(rec.TimestampNs)).UTC(),
		PID:       rec.PID,
		PPID:      rec.PPID,
		Comm:      cString(rec.Comm[:]),
		ExePath:   cString(rec.ExePath[:]),
		Args:      splitArgs(rec.Args[:]),
		SrcAddr:   net.IP(append([]byte(nil), rec.SrcAddr[:]...)),
		DstAddr:   net.IP(append([]byte(nil), rec.DstAddr[:]...)),
		SrcPort:   rec.SrcPort,
		DstPort:   rec.DstPort,
		TenantID:  tenantID,
		AgentID:   agentID,
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if rec.PayloadLen > 0 {
		payloadLen := int(rec.PayloadLen)
		if payloadLen > len(rec.Payload) {
			payloadLen = len(rec.Payload)
		}
		ev.Payload = append([]byte(nil), rec.Payload[:payloadLen]...)
	}
	return ev, nil
}

func copyEventRecord(dst *bpfEventRecord, raw []byte) {
	offset := 0
	dst.Kind = binary.LittleEndian.Uint32(raw[offset:])
	offset += 4
	dst.TimestampNs = binary.LittleEndian.Uint64(raw[offset:])
	offset += 8
	dst.PID = binary.LittleEndian.Uint32(raw[offset:])
	offset += 4
	dst.PPID = binary.LittleEndian.Uint32(raw[offset:])
	offset += 4
	copy(dst.SrcAddr[:], raw[offset:])
	offset += len(dst.SrcAddr)
	copy(dst.DstAddr[:], raw[offset:])
	offset += len(dst.DstAddr)
	dst.SrcPort = binary.LittleEndian.Uint16(raw[offset:])
	offset += 2
	dst.DstPort = binary.LittleEndian.Uint16(raw[offset:])
	offset += 2
	dst.PayloadLen = binary.LittleEndian.Uint32(raw[offset:])
	offset += 4
	copy(dst.Comm[:], raw[offset:])
	offset += len(dst.Comm)
	copy(dst.ExePath[:], raw[offset:])
	offset += len(dst.ExePath)
	copy(dst.Args[:], raw[offset:])
	offset += len(dst.Args)
	copy(dst.Payload[:], raw[offset:])
}

func eventKindFromWire(kind uint32) EventKind {
	switch kind {
	case 1:
		return EventKindProcessExec
	case 2:
		return EventKindProcessExit
	case 3:
		return EventKindTCPConnect
	case 4:
		return EventKindTCPAccept
	case 5:
		return EventKindTLSRead
	case 6:
		return EventKindTLSWrite
	default:
		return EventKindProcessExec
	}
}

func cString(raw []byte) string {
	if idx := strings.IndexByte(string(raw), 0); idx >= 0 {
		return strings.TrimSpace(string(raw[:idx]))
	}
	return strings.TrimSpace(string(raw))
}

func splitArgs(raw []byte) []string {
	value := cString(raw)
	if value == "" {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(value, "\x00", " "))
}

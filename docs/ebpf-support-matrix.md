# eBPF Sensor Support Matrix

## Overview

The MCPIDS eBPF sensor provides kernel-level visibility into process creation and network connections. It uses `cilium/ebpf` for userspace BPF program management and attaches kprobes/tracepoints to observe system calls.

The sensor is **optional**. On unsupported platforms it runs as a no-op stub (`StubManager`) that emits no events. All other MCPIDS components (gateway, control plane, agent) function normally without the eBPF sensor.

---

## Kernel Requirements

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Linux kernel | 5.8 | Required for `CAP_BPF` + `CAP_PERFMON` without root |
| BTF (BPF Type Format) | Enabled | Required for CO-RE (Compile Once, Run Everywhere) support |
| BPF ring buffer | 5.8 | Used for high-throughput event delivery |
| BPF maps (hash, array, ringbuf) | 4.6+ | Basic map support |
| Kprobes | 4.1+ | `sys_execve`, `tcp_connect` attachment points |
| Tracepoints | 4.7+ | `sched_process_exec`, `net/net_dev_xmit` |

> **Note**: While the kernel ≥ 4.1 supports the basic BPF infrastructure, MCPIDS requires ≥ 5.8 for unprivileged BPF and CO-RE support (no CGO, no compile-time BTF generation needed).

---

## Linux Distribution Support

| Distribution | Version | Status | Notes |
|-------------|---------|--------|-------|
| Ubuntu | 22.04 LTS (Jammy) | **Supported** | Kernel 5.15, BTF enabled |
| Ubuntu | 20.04 LTS (Focal) | **Supported** | Kernel 5.4 (default); needs HWE kernel 5.15+ |
| Ubuntu | 18.04 LTS (Bionic) | Not supported | Kernel 4.15, no CAP_BPF |
| Debian | 12 (Bookworm) | **Supported** | Kernel 6.1, BTF enabled |
| Debian | 11 (Bullseye) | Partial | Kernel 5.10, BTF enabled; unprivileged BPF off by default |
| RHEL / CentOS | 9.x | **Supported** | Kernel 5.14, BTF enabled |
| RHEL / CentOS | 8.x | Partial | Kernel 4.18 default; needs kernel-plus or UEK ≥ 5.4 |
| RHEL / CentOS | 7.x | Not supported | Kernel 3.x, no BPF program loading |
| Amazon Linux | 2023 | **Supported** | Kernel 6.1 |
| Amazon Linux | 2 | Partial | Kernel 5.10 (extras); `bpf_jit_enable` must be set |
| Fedora | 38+ | **Supported** | Kernel 6.x |
| Arch Linux | Current | **Supported** | Rolling release, kernel 6.x |
| Alpine Linux | 3.18+ | **Supported** | Kernel 6.1+, BTF enabled |
| Alpine Linux | 3.16, 3.17 | Partial | Kernel 5.15; may lack BTF depending on build |
| openSUSE Leap | 15.5 | **Supported** | Kernel 5.14 |
| Gentoo | Current | **Supported** | User-compiled kernel; requires BTF and BPF configs |

### Legend

| Status | Meaning |
|--------|---------|
| **Supported** | Full functionality, tested |
| Partial | Core BPF works but may require kernel tuning or elevated privileges |
| Not supported | eBPF sensor unavailable; no-op stub active |

---

## Cloud Provider Managed Kubernetes

| Platform | Default Kernel | Status | Notes |
|----------|---------------|--------|-------|
| Amazon EKS | 5.10+ (AL2) / 6.1+ (AL2023) | **Supported** | AL2023 nodes recommended |
| Google GKE | 6.1+ (Container-Optimized OS) | **Supported** | COS images have BTF enabled |
| Azure AKS | 5.15+ (Ubuntu 22.04) | **Supported** | Default Ubuntu node pools supported |
| DigitalOcean DOKS | 5.15+ | **Supported** | |
| Hetzner Cloud K8s | 6.1+ | **Supported** | |
| Oracle OKE | 5.15+ | **Supported** | |
| IBM IKS | 5.10+ | Partial | Check BTF availability per node image |

---

## Non-Linux Platforms

| Platform | eBPF Status | Sensor Mode |
|----------|-------------|------------|
| macOS (any) | Not supported | StubManager (no-op) |
| Windows (any) | Not supported | StubManager (no-op) |
| FreeBSD | Not supported | StubManager (no-op) |
| Linux (kernel < 5.8) | Not supported | StubManager (no-op) |

On non-Linux platforms, `sensor.IsSupported()` returns `false` and `sensor.Events()` returns a channel that never receives events. The system logs a warning at startup but continues normally.

---

## Required Capabilities

Running the sensor without root requires these Linux capabilities:

```
CAP_BPF       - load BPF programs and create BPF maps
CAP_PERFMON   - attach to perf events (kprobes, tracepoints)
CAP_NET_ADMIN - attach to network tracepoints (optional, for network monitoring)
```

**Kubernetes securityContext:**

```yaml
securityContext:
  capabilities:
    add:
      - CAP_BPF
      - CAP_PERFMON
      - CAP_NET_ADMIN
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
```

**Never** use `privileged: true` in production. The above capability set is the minimal required surface.

---

## Kernel Configuration Requirements

The target kernel must be compiled with these options:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y     # optional but recommended
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_TRACEPOINTS=y
CONFIG_DEBUG_INFO_BTF=y         # REQUIRED for CO-RE
CONFIG_DEBUG_INFO_BTF_MODULES=y # REQUIRED for module BTF
CONFIG_PERF_EVENTS=y
```

Check your kernel's BTF availability:
```bash
ls /sys/kernel/btf/vmlinux
# Should exist and be non-empty
```

Check unprivileged BPF is allowed:
```bash
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = allowed without root (ideal)
# 1 = requires CAP_BPF
# 2 = blocked entirely (need to be root)
```

On most modern distros, `unprivileged_bpf_disabled=1` and `CAP_BPF` is sufficient.

---

## Observed Event Types

When supported, the sensor emits the following event kinds:

| EventKind | Kprobe/Tracepoint | Description |
|-----------|-------------------|-------------|
| `process_exec` | `sched/sched_process_exec` | New process execution (captures command + args) |
| `process_exit` | `sched/sched_process_exit` | Process termination |
| `net_connect` | `tcp_connect` kprobe | Outbound TCP connection |
| `net_accept` | `inet_csk_accept` kretprobe | Inbound TCP connection accepted |
| `tls_write` | uprobe on `libssl.so:SSL_write` | TLS plaintext before encryption (optional) |
| `tls_read` | uprobe on `libssl.so:SSL_read` | TLS plaintext after decryption (optional) |

TLS uprobes are optional and require `libssl.so` to be present on the monitored system. They are disabled by default:

```yaml
sensor:
  attach_kprobes: true
  attach_uprobes: false   # set true to enable TLS plaintext capture
```

---

## Performance Impact

The eBPF sensor is designed to have minimal overhead:

| Operation | Overhead | Notes |
|-----------|---------|-------|
| Process exec kprobe | ~1–5µs per event | Per fork/exec call |
| TCP connect kprobe | ~1–3µs per event | Per connection |
| Ring buffer drain | ~10µs batch | Per ring buffer wakeup |
| Total CPU overhead | < 0.5% | Typical workloads |

The BPF programs run in the kernel verifier-checked sandbox and cannot cause kernel panics or infinite loops.

---

## Verification

After deploying the sensor, verify it is running:

```bash
# Check sensor is supported
curl -s http://localhost:9100/metrics | grep mcpids_sensor_supported
# mcpids_sensor_supported 1 (= supported)

# Check events are flowing
curl -s http://localhost:9100/metrics | grep mcpids_sensor_events_total
# mcpids_sensor_events_total{kind="process_exec"} 42
```

Check kernel BTF and kprobe attachment:
```bash
# List attached kprobes
cat /sys/kernel/debug/kprobes/list | grep mcpids

# List BPF programs
bpftool prog list | grep mcpids
```

---

## Troubleshooting

### "sensor: eBPF not supported on this platform"
Platform is non-Linux or `GOOS != linux`. Sensor runs as no-op stub. Expected on macOS/Windows dev machines.

### "sensor: failed to load BPF program: no such file"
`programs_dir` is configured but the compiled `.bpf.o` object files are missing.
The Docker image builds `/opt/mcpids/bpf/mcpids_trace.bpf.o`; for source builds,
compile `deploy/bpf/mcpids_trace.bpf.c` with clang and point `programs_dir` at
the resulting object directory.

### "permission denied: failed to attach kprobe"
The sensor process lacks `CAP_BPF` or `CAP_PERFMON`. Either:
- Add capabilities to the container securityContext
- Run as root (development only)
- Set `kernel.unprivileged_bpf_disabled=0` (not recommended for production)

### "BTF not found at /sys/kernel/btf/vmlinux"
The kernel was compiled without `CONFIG_DEBUG_INFO_BTF=y`. Options:
- Use a distro kernel that includes BTF (Ubuntu 22.04+, RHEL 9+, Debian 12+)
- Provide a pre-built BTF file via `sensor.btf_custom_path`

### High event drop rate
The ring buffer is filling faster than the userspace consumer can drain it. Increase `sensor.event_buffer_size` (default: 1024) or reduce sensor verbosity by disabling less critical event types.

#include "mcpids_events.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>

#define MCPIDS_AF_INET 2
#define MCPIDS_AF_INET6 10

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Maximum TLS plaintext bytes captured per event (matches mcpids_event.payload). */
#define MCPIDS_TLS_PAYLOAD_MAX 256

/* Stash accept4 args so the exit probe can read the filled-in peer sockaddr. */
struct accept4_args {
	__u64 upeer_sockaddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct accept4_args);
} accept4_inflight SEC(".maps");

/*
 * Stash SSL_read's output buffer pointer from function entry so the uretprobe
 * can read the now-populated data on return.
 */
struct ssl_read_args {
	__u64 buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct ssl_read_args);
} ssl_read_inflight SEC(".maps");

struct sys_enter_connect_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	__s32 __syscall_nr;
	__u64 fd;
	__u64 uservaddr;
	__u64 addrlen;
};

struct sys_enter_accept4_ctx {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__s32 __syscall_nr;
	__u64 fd;
	__u64 upeer_sockaddr;
	__u64 upeer_addrlen;
	__u64 flags;
};

struct sys_exit_accept4_ctx {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__s32 __syscall_nr;
	__s64 ret;
};

static __always_inline struct mcpids_event *reserve_event(__u32 kind)
{
	struct mcpids_event *event;
	__u64 pid_tgid;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	pid_tgid = bpf_get_current_pid_tgid();
	event->kind = kind;
	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = (__u32)(pid_tgid >> 32);
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	return event;
}

SEC("tracepoint/sched/sched_process_exec")
int mcpids_process_exec(void *ctx)
{
	struct mcpids_event *event;

	(void)ctx;

	event = reserve_event(MCPIDS_EVENT_KIND_PROCESS_EXEC);
	if (!event)
		return 0;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int mcpids_process_exit(void *ctx)
{
	struct mcpids_event *event;

	(void)ctx;

	event = reserve_event(MCPIDS_EVENT_KIND_PROCESS_EXIT);
	if (!event)
		return 0;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int mcpids_tcp_connect(struct sys_enter_connect_ctx *ctx)
{
	struct mcpids_event *event;
	__u16 family = 0;

	event = reserve_event(MCPIDS_EVENT_KIND_TCP_CONNECT);
	if (!event)
		return 0;

	if (ctx && ctx->uservaddr &&
	    bpf_probe_read_user(&family, sizeof(family), (const void *)ctx->uservaddr) == 0) {
		if (family == MCPIDS_AF_INET) {
			struct sockaddr_in in4 = {};
			if (bpf_probe_read_user(&in4, sizeof(in4),
						(const void *)ctx->uservaddr) != 0)
				goto out;
			event->dst_addr[10] = 0xff;
			event->dst_addr[11] = 0xff;
			__builtin_memcpy(&event->dst_addr[12], &in4.sin_addr.s_addr,
					 sizeof(in4.sin_addr.s_addr));
			event->dst_port = bpf_ntohs(in4.sin_port);
		} else if (family == MCPIDS_AF_INET6) {
			struct sockaddr_in6 in6 = {};
			if (bpf_probe_read_user(&in6, sizeof(in6),
						(const void *)ctx->uservaddr) != 0)
				goto out;
			__builtin_memcpy(event->dst_addr, &in6.sin6_addr.in6_u.u6_addr8,
					 sizeof(event->dst_addr));
			event->dst_port = bpf_ntohs(in6.sin6_port);
		}
	}

out:
	bpf_ringbuf_submit(event, 0);

	return 0;
}

/*
 * mcpids_accept4_enter - stash the peer-sockaddr pointer so the exit probe can
 * read it after the kernel has filled it in.
 */
SEC("tracepoint/syscalls/sys_enter_accept4")
int mcpids_accept4_enter(struct sys_enter_accept4_ctx *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct accept4_args args = {};

	args.upeer_sockaddr = ctx->upeer_sockaddr;
	bpf_map_update_elem(&accept4_inflight, &pid_tgid, &args, BPF_ANY);
	return 0;
}

/*
 * mcpids_tcp_accept - emit a TCP_ACCEPT event when accept4 returns a valid fd.
 * The kernel has filled in the peer sockaddr by the time sys_exit fires, so we
 * can read the remote address directly from user space.
 */
SEC("tracepoint/syscalls/sys_exit_accept4")
int mcpids_tcp_accept(struct sys_exit_accept4_ctx *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct accept4_args *args;
	struct mcpids_event *event;
	__u16 family = 0;

	args = bpf_map_lookup_elem(&accept4_inflight, &pid_tgid);
	if (!args)
		return 0;
	bpf_map_delete_elem(&accept4_inflight, &pid_tgid);

	/* Only emit on successful accept (ret is the new fd >= 0). */
	if (ctx->ret < 0)
		return 0;

	event = reserve_event(MCPIDS_EVENT_KIND_TCP_ACCEPT);
	if (!event)
		return 0;

	/*
	 * Read the peer (remote client) address that the kernel wrote into the
	 * user-supplied sockaddr buffer.  Store it as src_addr/src_port since the
	 * remote side is the initiating "source" of this inbound connection.
	 */
	if (args->upeer_sockaddr &&
	    bpf_probe_read_user(&family, sizeof(family),
			       (const void *)args->upeer_sockaddr) == 0) {
		if (family == MCPIDS_AF_INET) {
			struct sockaddr_in in4 = {};
			if (bpf_probe_read_user(&in4, sizeof(in4),
						(const void *)args->upeer_sockaddr) != 0)
				goto out;
			/* Encode IPv4-mapped-IPv6: ::ffff:<addr> */
			event->src_addr[10] = 0xff;
			event->src_addr[11] = 0xff;
			__builtin_memcpy(&event->src_addr[12], &in4.sin_addr.s_addr,
					 sizeof(in4.sin_addr.s_addr));
			event->src_port = bpf_ntohs(in4.sin_port);
		} else if (family == MCPIDS_AF_INET6) {
			struct sockaddr_in6 in6 = {};
			if (bpf_probe_read_user(&in6, sizeof(in6),
						(const void *)args->upeer_sockaddr) != 0)
				goto out;
			__builtin_memcpy(event->src_addr, &in6.sin6_addr.in6_u.u6_addr8,
					 sizeof(event->src_addr));
			event->src_port = bpf_ntohs(in6.sin6_port);
		}
	}

out:
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/*
 * mcpids_tls_write - uprobe on SSL_write entry.
 *
 * Signature: int SSL_write(SSL *ssl, const void *buf, int num)
 *   arg1 (SSL *)    : PT_REGS_PARM1 - ignored
 *   arg2 (void *buf): PT_REGS_PARM2 - plaintext buffer (already populated)
 *   arg3 (int num)  : PT_REGS_PARM3 - bytes to write
 *
 * The buffer is valid at entry, so we capture the payload immediately.
 * Attach to: uprobe/SSL_write in libssl.so
 */
SEC("uprobe/SSL_write")
int mcpids_tls_write(struct pt_regs *ctx)
{
	struct mcpids_event *event;
	__u64 buf_addr;
	__s32 len;
	__u32 copy_len;

	buf_addr = PT_REGS_PARM2(ctx);
	len = (__s32)PT_REGS_PARM3(ctx);
	if (len <= 0 || !buf_addr)
		return 0;

	event = reserve_event(MCPIDS_EVENT_KIND_TLS_WRITE);
	if (!event)
		return 0;

	copy_len = (__u32)len < MCPIDS_TLS_PAYLOAD_MAX
		? (__u32)len : MCPIDS_TLS_PAYLOAD_MAX;
	if (bpf_probe_read_user(event->payload, copy_len, (const void *)buf_addr) == 0)
		event->payload_len = copy_len;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

/*
 * mcpids_tls_read_enter - uprobe on SSL_read entry.
 *
 * Stash the output buffer pointer so the uretprobe can read it after the
 * kernel has populated it.
 *
 * Signature: int SSL_read(SSL *ssl, void *buf, int num)
 * Attach to: uprobe/SSL_read in libssl.so
 */
SEC("uprobe/SSL_read")
int mcpids_tls_read_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_read_args args = {};

	args.buf = PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&ssl_read_inflight, &pid_tgid, &args, BPF_ANY);
	return 0;
}

/*
 * mcpids_tls_read - uretprobe on SSL_read return.
 *
 * The return value is the number of bytes placed into the buffer.  Emit the
 * decrypted payload if the read succeeded (ret > 0).
 * Attach to: uretprobe/SSL_read in libssl.so
 */
SEC("uretprobe/SSL_read")
int mcpids_tls_read(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_read_args *args;
	struct mcpids_event *event;
	__s64 ret;
	__u32 copy_len;

	args = bpf_map_lookup_elem(&ssl_read_inflight, &pid_tgid);
	if (!args)
		return 0;
	bpf_map_delete_elem(&ssl_read_inflight, &pid_tgid);

	ret = (__s64)PT_REGS_RC(ctx);
	if (ret <= 0 || !args->buf)
		return 0;

	event = reserve_event(MCPIDS_EVENT_KIND_TLS_READ);
	if (!event)
		return 0;

	copy_len = (__u32)ret < MCPIDS_TLS_PAYLOAD_MAX
		? (__u32)ret : MCPIDS_TLS_PAYLOAD_MAX;
	if (bpf_probe_read_user(event->payload, copy_len, (const void *)args->buf) == 0)
		event->payload_len = copy_len;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

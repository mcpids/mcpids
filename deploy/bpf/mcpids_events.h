#ifndef MCPIDS_EVENTS_H
#define MCPIDS_EVENTS_H

#include <linux/types.h>

enum mcpids_event_kind {
	MCPIDS_EVENT_KIND_UNSPECIFIED = 0,
	MCPIDS_EVENT_KIND_PROCESS_EXEC = 1,
	MCPIDS_EVENT_KIND_PROCESS_EXIT = 2,
	MCPIDS_EVENT_KIND_TCP_CONNECT = 3,
	MCPIDS_EVENT_KIND_TCP_ACCEPT = 4,
	MCPIDS_EVENT_KIND_TLS_READ = 5,
	MCPIDS_EVENT_KIND_TLS_WRITE = 6,
};

struct mcpids_event {
	__u32 kind;
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u16 src_port;
	__u16 dst_port;
	__u32 payload_len;
	char comm[16];
	char exe_path[256];
	char args[256];
	__u8 payload[256];
};

#endif

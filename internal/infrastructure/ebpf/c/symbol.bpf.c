// symbol.bpf.c — exact positive runtime symbol-hit observer for reachability (#1060).
//
// Userspace attaches this program as a uprobe to one curated affected function. A hit is
// positive evidence only: failure to attach, a full ring buffer, or silence never means the
// function did not execute.
#include "detect.bpf.h"

struct runtime_symbol_event {
	__u64 ktime_ns;
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} runtime_symbol_events SEC(".maps");

SEC("uprobe")
int runtime_symbol_hit(void *ctx)
{
	struct runtime_symbol_event *e = bpf_ringbuf_reserve(&runtime_symbol_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ktime_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";

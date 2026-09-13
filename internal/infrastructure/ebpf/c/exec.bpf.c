// exec.bpf.c — process-execution observer (detection class "process") plus positive runtime reachability
// observations. Runtime observations are raise-only evidence: these programs emit only observed exec,
// executable file-backed mmap, and uprobe hits. They never emit absence or an unreachable verdict.
#include "detect.bpf.h"

#define PROT_EXEC_BIT 0x4

struct exec_event {
	__u64 ktime_ns; // kernel-monotonic occurred-at (bpf_ktime_get_ns); userspace maps it to wall-clock
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
	char filename[PATH_LEN];
	char arg1[ARG_LEN];
	char arg2[ARG_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} exec_events SEC(".maps");

// runtime_exec_event is emitted from sched_process_exec, after exec succeeded. Using sys_enter_execve
// here would incorrectly claim execution for an exec that later failed.
struct runtime_exec_event {
	__u64 ktime_ns;
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} runtime_exec_events SEC(".maps");

// mmap arguments are paired across enter/exit by pid+tid so library evidence is emitted only after a
// successful executable file-backed mapping. Userspace resolves the returned mapping address through
// /proc/<pid>/maps to recover path, device and inode without bpf_d_path / CO-RE dependencies.
struct runtime_mmap_args {
	__s64 fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct runtime_mmap_args);
} runtime_mmap_args SEC(".maps");

struct runtime_map_event {
	__u64 ktime_ns;
	__u64 addr;
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} runtime_map_events SEC(".maps");

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

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_execve(struct sys_enter_ctx *ctx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e)
		return 0; // ring full — drop the record, never block the exec

	e->ktime_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	// argv is a user array of char*; read argv[1] and argv[2] (the first real arguments). argv[0] is the
	// program name, which is already covered by comm/filename.
	e->arg1[0] = 0;
	e->arg2[0] = 0;
	const char *const *argv = (const char *const *)ctx->args[1];
	if (argv) {
		const char *p1 = 0, *p2 = 0;
		bpf_probe_read_user(&p1, sizeof(p1), &argv[1]);
		if (p1)
			bpf_probe_read_user_str(&e->arg1, sizeof(e->arg1), p1);
		bpf_probe_read_user(&p2, sizeof(p2), &argv[2]);
		if (p2)
			bpf_probe_read_user_str(&e->arg2, sizeof(e->arg2), p2);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int runtime_binary_exec(void *ctx)
{
	struct runtime_exec_event *e = bpf_ringbuf_reserve(&runtime_exec_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ktime_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int runtime_mmap_enter(struct sys_enter_ctx *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 prot = ctx->args[2];
	__s64 fd = (__s64)ctx->args[4];

	// Delete first so a stale entry can never survive an unrelated mmap call if an earlier exit was
	// missed while this program was being attached.
	bpf_map_delete_elem(&runtime_mmap_args, &key);
	if (!(prot & PROT_EXEC_BIT) || fd < 0)
		return 0;

	struct runtime_mmap_args args = {.fd = fd};
	bpf_map_update_elem(&runtime_mmap_args, &key, &args, BPF_ANY);
	return 0;
}

struct sys_exit_ctx {
	unsigned long long unused;
	long syscall_nr;
	long ret;
};

SEC("tracepoint/syscalls/sys_exit_mmap")
int runtime_mmap_exit(struct sys_exit_ctx *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct runtime_mmap_args *args = bpf_map_lookup_elem(&runtime_mmap_args, &key);
	if (!args)
		return 0;

	// Copy before delete because the map value pointer is invalid afterwards.
	__s64 fd = args->fd;
	bpf_map_delete_elem(&runtime_mmap_args, &key);
	if (ctx->ret < 0 || fd < 0)
		return 0;

	struct runtime_map_event *e = bpf_ringbuf_reserve(&runtime_map_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ktime_ns = bpf_ktime_get_ns();
	e->addr = (__u64)ctx->ret;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// runtime_symbol_hit is attached by userspace as a uprobe to one exact curated function. Each attached
// probe gets its own collection/ring buffer, so userspace can stamp the exact path+symbol without
// bpf_get_attach_cookie (which would silently raise the minimum kernel requirement to 5.15).
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

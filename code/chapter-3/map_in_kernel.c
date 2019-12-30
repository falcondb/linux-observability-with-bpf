#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size) {
	return syscall(__NR_bpf, cmd, attr, size);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
  union bpf_attr attr;

	memset(&attr, '\0', sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = map_flags;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
  int fd = bpf(BPF_MAP_CREATE, &my_map, sizeof(my_map));
  char msg[32];
  sprintf(msg, "fd: %d", fd);
  bpf_trace_printk(msg, sizeof(msg));
  sprintf(msg, "map_data: %d", map_data[0].fd);
  bpf_trace_printk(msg, sizeof(msg));
  return 0;
}

char _license[] SEC("license") = "GPL";

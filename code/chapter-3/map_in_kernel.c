#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
  union bpf_attr my_map {
  .map_type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 10,
  .map_flags = BPF_F_NO_PREALLOC,
  };
  int fd = bpf(BPF_MAP_CREATE, &my_map, sizeof(my_map));
  char msg[32];
  sprintf(msg, "fd: %d", fd);
  bpf_trace_printk(msg, sizeof(msg));
  return 0;
}

char _license[] SEC("license") = "GPL";

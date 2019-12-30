#include <linux/bpf.h>
#include <string.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <stdio.h>
#include <bpf_helpers.h>

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps")  my_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 10,
	.map_flags = BPF_F_NO_PREALLOC,
};

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
	int key = 0;
	int* count = 0;
	int value = 0;
	char msg[] = "Counting in kernel!";
	char err[] = "error in kernel!";

	//result = bpf_map_update_elem(&my_map, &key, &count, 0);
	count = bpf_map_lookup_elem(&my_map, &key);
	if (!count) {
		bpf_map_update_elem(&my_map, &key, &value, 0);
		bpf_trace_printk(err, sizeof(err));
	}
	else {
		value = *count + 1;
		bpf_map_update_elem(&my_map, &key, &value, 0);
  	bpf_trace_printk(msg, sizeof(msg));
	}

  // int fd = syscall(__NR_bpf, BPF_MAP_CREATE, &my_map, sizeof(my_map));
  // char msg[32];
  // sprintf(msg, "fd: %d", fd);
  // bpf_trace_printk(msg, sizeof(msg));
  // sprintf(msg, "map_data: %d", map_data[0].fd);
  // bpf_trace_printk(msg, sizeof(msg));
  return 0;
}

char _license[] SEC("license") = "GPL";

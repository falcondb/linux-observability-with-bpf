#include <linux/bpf.h>
#include <string.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <stdio.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size) {
	return syscall(__NR_bpf, cmd, attr, size);
}

int main(int argc, char **argv) {
  union bpf_attr attr;
	memset(&attr, '\0', sizeof(attr));

	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(int);
	attr.value_size = sizeof(int);
	attr.max_entries = 10;
	attr.map_flags = BPF_F_NO_PREALLOC;

  int fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

  char msg[32];
  sprintf(msg, "fd: %d", fd);
  printf("%s", msg);
  return fd;
}

char _license[] SEC("license") = "GPL";

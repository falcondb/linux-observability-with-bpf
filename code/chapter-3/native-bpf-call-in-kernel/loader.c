#include "bpf_load.h"
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Need the object file name\n");
    return -1;
  }

  if (load_bpf_file(argv[1]) != 0) {
    printf("The kernel didn't load the BPF program\n");
    return -1;
  }

  read_trace_pipe();

  return 0;
}

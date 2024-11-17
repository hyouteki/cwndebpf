#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

#define CwndMapPath "/sys/fs/bpf/CwndMap"

int main() {
	__u32 key = 0, value;

    int cwnd_map_fd = bpf_obj_get(CwndMapPath);
	if (cwnd_map_fd < 0) {
        fprintf(stderr, "error: failed to open CwndMap: %s\n", strerror(errno));
        return 1;
    }

    if (bpf_map_lookup_elem(cwnd_map_fd, &key, &value) < 0) {
        fprintf(stderr, "error: failed to lookup element in CwndMap: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stdout, "%u\n", value);

    return 0;
}

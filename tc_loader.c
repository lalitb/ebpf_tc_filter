#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <getopt.h>

// libbpf headers
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DEFAULT_IFNAME "lo"
#define DEFAULT_PROG_SECTION "hello_tc_prog"
#define CGROUP_MAP_NAME "target_cgroup"

static volatile int keep_running = 1;

static void int_exit(int sig) {
    keep_running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -i, --interface <name>   Network interface (default: lo)\n"
        "  --inject-traceparent     Use traceparent-injecting eBPF program\n"
        "  --cgroup <cgroup_id>     Only act on this cgroup id\n"
        "  --ingress                Attach to ingress (default)\n"
        "  --egress                 Attach to egress\n"
        "  -h, --help               Show this help message\n",
        prog
    );
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_tc_hook tc_hook = {};
    struct bpf_tc_opts tc_opts = {};
    int err = 0, prog_fd = -1;
    char *ifname = DEFAULT_IFNAME;
    char *bpf_obj_file = "tc_icmp_filter.o";
    char *prog_section = DEFAULT_PROG_SECTION;
    bool inject_traceparent = false;
    bool use_cgroup = false;
    uint64_t cgroup_id = 0;
    int attach_point = BPF_TC_INGRESS;

    // Argument parsing
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"inject-traceparent", no_argument, 0, 1},
        {"cgroup", required_argument, 0, 2},
        {"ingress", no_argument, 0, 3},
        {"egress", no_argument, 0, 4},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0, opt;
    while ((opt = getopt_long(argc, argv, "i:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 1:
                inject_traceparent = true;
                bpf_obj_file = "tc_inject_traceparent.o";
                prog_section = "inject_traceparent";
                break;
            case 2:
                use_cgroup = true;
                cgroup_id = strtoull(optarg, NULL, 0);
                break;
            case 3:
                attach_point = BPF_TC_INGRESS;
                break;
            case 4:
                attach_point = BPF_TC_EGRESS;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 1;
        }
    }

    printf("Attaching to interface: %s\n", ifname);
    printf("Attach point: %s\n", attach_point == BPF_TC_INGRESS ? "ingress" : "egress");
    printf("eBPF program: %s (section: %s)\n", bpf_obj_file, prog_section);
    if (inject_traceparent)
        printf("Mode: Inject traceparent header\n");
    if (use_cgroup)
        printf("Filtering for cgroup id: %llu\n", (unsigned long long)cgroup_id);

    // Set up signal handler
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    // Load the BPF object
    obj = bpf_object__open_file(bpf_obj_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", bpf_obj_file);
        return 1;
    }

    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    // Find the TC program in the loaded object
    prog = bpf_object__find_program_by_name(obj, prog_section);
    if (!prog) {
        fprintf(stderr, "Failed to find program section '%s'\n", prog_section);
        bpf_object__close(obj);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get TC program FD\n");
        bpf_object__close(obj);
        return 1;
    }

    // If cgroup filter requested, update the map
    if (use_cgroup) {
        int map_fd = bpf_object__find_map_fd_by_name(obj, CGROUP_MAP_NAME);
        if (map_fd < 0) {
            fprintf(stderr, "Failed to find BPF map '%s'\n", CGROUP_MAP_NAME);
            bpf_object__close(obj);
            return 1;
        }
        __u32 key = 0;
        if (bpf_map_update_elem(map_fd, &key, &cgroup_id, BPF_ANY) != 0) {
            perror("bpf_map_update_elem (target_cgroup)");
            bpf_object__close(obj);
            return 1;
        }
        printf("Set target_cgroup map to %llu\n", (unsigned long long)cgroup_id);
    }

    // Set up TC hook
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = if_nametoindex(ifname);
    if (!tc_hook.ifindex) {
        fprintf(stderr, "Failed to get interface index for %s\n", ifname);
        bpf_object__close(obj);
        return 1;
    }
    tc_hook.attach_point = attach_point;

    // Create TC qdisc
    err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    // Set up TC options
    tc_opts.sz = sizeof(tc_opts);
    tc_opts.prog_fd = prog_fd;

    // Attach the TC program
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC program: %d\n", err);

        // Clean up TC hook
        bpf_tc_hook_destroy(&tc_hook);

        bpf_object__close(obj);
        return 1;
    }

    printf("TC program successfully attached to %s (%s)\n", ifname,
           attach_point == BPF_TC_INGRESS ? "ingress" : "egress");
    printf("Press Ctrl+C to detach and exit...\n");

    // Keep the program running until interrupted
    while (keep_running) {
        sleep(1);
    }

    // Detach and clean up
    tc_opts.flags = BPF_TC_F_REPLACE;
    err = bpf_tc_detach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to detach TC program: %d\n", err);
    }

    err = bpf_tc_hook_destroy(&tc_hook);
    if (err) {
        fprintf(stderr, "Failed to destroy TC hook: %d\n", err);
    }

    bpf_object__close(obj);
    printf("Program detached and resources cleaned up\n");
    return 0;
}
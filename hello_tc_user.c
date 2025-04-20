// hello_tc_user.c
// User space program to load and attach TC eBPF program without using tc command

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>

// libbpf headers
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Default interface
#define DEFAULT_IFNAME "lo"

static volatile int keep_running = 1;

// Signal handler for clean exit
static void int_exit(int sig)
{
    keep_running = 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_tc_hook tc_hook = {};
    struct bpf_tc_opts tc_opts = {};
    int err, prog_fd;
    char *ifname = DEFAULT_IFNAME;

    // Accept interface name as command line argument
    if (argc > 1) {
        ifname = argv[1];
    }

    // Set up signal handler
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    // Load the BPF object
    obj = bpf_object__open_file("hello_tc_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
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
    prog = bpf_object__find_program_by_name(obj, "hello_tc_prog");
    if (!prog) {
        // Try by section name if available in your libbpf version
        fprintf(stderr, "Failed to find program by name, trying alternative methods...\n");
        
        // Iterate through all programs in the object
        struct bpf_program *pos;
        bpf_object__for_each_program(pos, obj) {
            const char *sec_name = bpf_program__section_name(pos);
            if (sec_name && strcmp(sec_name, "tc") == 0) {
                prog = pos;
                break;
            }
        }
        
        if (!prog) {
            fprintf(stderr, "Failed to find TC program in loaded object\n");
            bpf_object__close(obj);
            return 1;
        }
    }

    // Get the file descriptor of the loaded program
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get TC program FD\n");
        bpf_object__close(obj);
        return 1;
    }

    // Set up TC hook
    tc_hook.sz = sizeof(tc_hook);
    tc_hook.ifindex = if_nametoindex(ifname);
    if (!tc_hook.ifindex) {
        fprintf(stderr, "Failed to get interface index for %s\n", ifname);
        bpf_object__close(obj);
        return 1;
    }
    tc_hook.attach_point = BPF_TC_INGRESS;

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
        tc_hook.attach_point = BPF_TC_INGRESS;
        bpf_tc_hook_destroy(&tc_hook);
        
        bpf_object__close(obj);
        return 1;
    }

    printf("TC program successfully attached to %s (ingress)\n", ifname);
    printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see output\n");
    printf("Press Ctrl+C to detach and exit...\n");

    // Keep the program running until interrupted
    while (keep_running) {
        sleep(1);
    }

    // Detach and clean up
    memset(&tc_opts, 0, sizeof(tc_opts));
    tc_opts.sz = sizeof(tc_opts);
    tc_opts.flags = BPF_TC_F_REPLACE;
    tc_hook.attach_point = BPF_TC_INGRESS;
    
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
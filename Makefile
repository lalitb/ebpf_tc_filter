# Makefile for eBPF TC Hello World using libbpf

# Compiler and flags
CC := clang
CFLAGS := -g -O2 -Wall

# eBPF program (kernel space)
BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86

# User space program
LIBS := -lbpf -lelf

# Target files
BPF_PROG_1 := tc_icmp_filter.o
BPF_PROG_2 := tc_inject_traceparent.o

USER_PROG := hello_tc_user

# Default target
all: $(BPF_PROG_1) $(BPF_PROG_2) $(USER_PROG)

# Compile the BPF program (kernel space part)
$(BPF_PROG_1): tc_icmp_filter.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

$(BPF_PROG_2): tc_inject_traceparent.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

# Compile and link the user space program
$(USER_PROG): tc_loader.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Show info about the BPF object file
check-bpf:
	file $(BPF_PROG_1)
	file

# Clean up
clean:
	rm -f $(BPF_PROG_1) $(BPF_PROG_2) $(USER_PROG)

# Help target
help:
	@echo "Makefile for eBPF TC Hello World using libbpf"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build both kernel and user space programs (default)"
	@echo "  clean     - Remove all generated files"
	@echo "  check-bpf - Show info about hello_tc_kern.o"
	@echo "  help      - Show this help message"

.PHONY: all clean help check-bpf
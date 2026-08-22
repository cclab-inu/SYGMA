# Set arguments accordingly
CLANG ?= clang-14
STRIP ?= llvm-strip-14
OBJCOPY ?= llvm-objcopy-14
#CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CFLAGS := -O2 -g $(CFLAGS)

# Generate the amd64 bpf2go bindings and a standalone monitoring.o.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...
	clang -O2 -target bpf -D__TARGET_ARCH_X86 -c monitoring.c -o monitoring.o -g

# This will clean up everything generated automatically.
clean:
	rm -f *.o
	rm -f bpf_x86_bpfel.go
	rm -f core

# This will autogenerate files and then will build.
build:
	make generate
	go build -buildvcs=false -o core .

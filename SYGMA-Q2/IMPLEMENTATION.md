# SYGMA: A Zero-Trust syscall Enforcement Framework for Containerized Microservices

## Environment

| Application | Version     | Application | Version            |
| ----------- | ----------- | ----------- | ------------------ |
| Ubuntu      | 22.04.5 LTS | Kernel      | 5.15.0-168-generic |
| Kubernetes  | 1.29.1      | containerd  | 2.2.1              |
| runc        | 1.3.4       | go          | 1.24.11            |



## Setup

```shell
# SETUP
$ sudo apt install -y gcc make libbpf-dev
# Optional only when rebuilding the checked-in BPF object:
$ sudo apt install -y clang-14 llvm-14 gcc-multilib

# All SYGMA source needed by the anonymous build is already included in this
# profile. No external source checkout is part of the canonical workflow.

$ cat /sys/kernel/security/lsm
# If it does not display as shown below, you need to edit it using the vi editor.
# GRUB_CMDLINE_LINUX="lsm=ndlock,lockdown,yama,integrity,apparmor,bpf"
$ sudo vi /etc/default/grub

$ sudo update-grub2
$ sudo init 6
```



## Deploy SYGMA

```shell
# Predeployment phase
# Deploy SYGMA & SYGMAConfig

$ cd SYGMA-Q2
$ ./local-images.sh build
# Copy artifacts/local/ with the same source tree and run this on every
# eligible Kubernetes node.
$ ./local-images.sh load
# Run once from the control-plane/build host after every node is loaded.
$ ./local-images.sh deploy

$ kubectl apply -f manifest/nginx-sygmaconfig.yaml
$ kubectl get pods -o wide
# Wait untill second pod fully deleted
```



## Deploy policy adapted pod

```shell
# Pod deployment phase
$ kubectl apply -f nginx_sygma.yaml
```

## Hybrid enforcement routing

The enforcement routes are synchronized with
`systematic_analysis/output-effective-n-full-patched` for the evaluated Linux
5.15 kernel build.

- The four syscalls certified for both mechanisms (`clone`, `fork`, `vfork`,
  and `clone3`) use the earlier SIGKILL checkpoint.
- The remaining 142 LSM-certified syscalls use a syscall-entry kprobe to
  evaluate the transition and arm `lsm_block_map`; the certified BPF LSM hook
  consumes that entry and returns `-EPERM`.
- The wrapper allows those 146 dedicated routes and the four asynchronous
  bypass syscalls through seccomp.
- Every other syscall returns `SECCOMP_RET_TRACE` and is enforced through
  `ptrace_notify`.

The source report contains 146 LSM-E syscalls in total. The LSM route count is
142 because the four overlapping syscalls are deliberately assigned to
SIGKILL, not counted twice.

After changing `monitoring.c`, regenerate the embedded BPF object before
building the daemon:

```shell
cd sygma_eBPF
make generate
go build -buildvcs=false -o core .
```



## Log statics

```shell
# Watch log
$ kubectl logs ds/core
```

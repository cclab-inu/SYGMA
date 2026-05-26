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
$ sudo apt install -y clang-14 llvm-14 gcc-multilib

$ git clone https://github.com/gjwls/cilium-eBPF-starter.git
$ cd cilium-eBPF-starter
$ sudo apt install make
$ make build
$ sudo apt install -y libbpf-dev

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

$ cd sygma_final/manifest
$ ./deploy.sh

$ kubectl apply -f nginx-sygmaconfig.yaml
$ kubectl get pods -o wide
# Wait untill second pod fully deleted
```



## Deploy policy adapted pod

```shell
# Pod deployment phase
$ kubectl apply -f nginx_sygma.yaml
```



## Log statics

```shell
# Watch log
$ kubectl logs ds/core
```


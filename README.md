# tcptracer-bpf

tcptracer-bpf is an eBPF program using kprobes to trace TCP events. It's
built as an object file that can be used with the [gobpf elf package](https://github.com/iovisor/gobpf).
It does not have any run-time dependencies and adapts to the currently running
kernel at run-time. It does not use [bcc](https://github.com/iovisor/bcc)
because that would introduce a run-time dependency on the kernel headers.

See `tests/tracer.go` for an example how to use tcptracer-bpf with gobpf.

## Build the elf object

```
make
```

The object file can be found in `ebpf/ebpf.o`.

## Test

```
cd tests
make
sudo ./run
```

## Vendoring

We use [gvt](https://github.com/FiloSottile/gvt).

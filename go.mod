module github.com/Gthulhu/scx_goland_core

go 1.22.6

require github.com/aquasecurity/libbpfgo v0.8.0-libbpf-1.5

require (
	github.com/Gthulhu/plugin v0.0.0-20250905063209-71c1f8ba7eb4 // indirect
	github.com/c9s/goprocinfo v0.0.0-20210130143923-c95fcf8c64a8 // indirect
	github.com/cilium/ebpf v0.17.1 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

replace github.com/aquasecurity/libbpfgo => ./libbpfgo

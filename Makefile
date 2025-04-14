

filter ?=

run: build
	sudo ./ebpf-program-support-pcap-filter-demo $(filter)

generate:
	go generate ./...

build: generate
	go build -tags dynamic

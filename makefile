.PHONY: docker

generate:
	go generate -C cmd/01_helloworld .
	go generate -C cmd/02_tracepoint_execve .

run-01: generate
	go run -C cmd/01_helloworld -exec sudo . 

run-02: generate
	go run -C cmd/02_tracepoint_execve -exec sudo . 

docker:
	docker build -f Dockerfile -t ebpf:latest .
	docker build -f Dockerfile -t ebpf:latest .

build: generate
	mkdir -p bin/
	go build -o bin/01_helloworld ebpf/cmd/01_helloworld 
	go build -o bin/02_tracepoint_execve ebpf/cmd/02_tracepoint_execve 

docker-run: docker
	docker run --rm --cap-add=CAP_BPF --cap-add=CAP_SYS_ADMIN -v /sys/kernel/tracing:/sys/kernel/tracing:ro -ti ebpf:latest

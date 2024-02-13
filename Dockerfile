FROM golang:latest

ARG EXEC_NAME

WORKDIR /go/app

RUN apt update \
  && apt install -y clang llvm bpftool libbpf-dev \
  && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum .
RUN go mod download && go mod verify

COPY . .
RUN make build

CMD ["bash"]


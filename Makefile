all: rfront

.PHONY: rfront
rfront:
	go build -o rfront cmd/rfront/*.go

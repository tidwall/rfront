all: redfront

.PHONY: redfront
redfront:
	go build -o redfront cmd/redfront/*.go

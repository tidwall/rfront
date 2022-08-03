package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func isLeadershipError(emsg string) bool {
	switch {
	case strings.HasPrefix(emsg, "MOVED "):
		return true
	case strings.HasPrefix(emsg, "CLUSTERDOWN "):
		return true
	case strings.HasPrefix(emsg, "TRYAGAIN "):
		return true
	case strings.HasPrefix(emsg, "TRY "):
		return true
	case strings.HasPrefix(emsg, "LOADING "):
		return true
	case emsg == "ERR node is not the leader":
		return true
	case emsg == "ERR leadership lost while committing log":
		return true
	case emsg == "ERR leadership transfer in progress":
		return true
	}
	return false
}

func hijackRaw(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	h, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("response cannot be hijacked")
	}
	conn, brw, err := h.Hijack()
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	if brw.Reader.Buffered() > 0 || brw.Writer.Buffered() > 0 {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

var errInvalidRESP = errors.New("invalid resp")

// readRESP from reader and append to dst.
func readRESP(dst []byte, r *bufio.Reader) ([]byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	dst = append(dst, b)
	mark := len(dst)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	dst = append(dst, line...)
	switch b {
	case '-', '+', ':':
		return dst, nil
	case '*', '$':
		buf := dst[mark : len(dst)-1]
		if len(buf) > 0 && buf[len(buf)-1] == '\r' {
			buf = buf[:len(buf)-1]
		}
		n, err := strconv.ParseInt(string(buf), 10, 64)
		if err != nil {
			return nil, errInvalidRESP
		}
		if b == '*' {
			for n > 0 {
				dst, err = readRESP(dst, r)
				if err != nil {
					return nil, err
				}
				n--
			}
		} else {
			if n >= 0 {
				data := make([]byte, n+2)
				_, err := io.ReadFull(r, data)
				if err != nil {
					return nil, err
				}
				dst = append(dst, data...)
			}
		}
	default:
		return nil, errInvalidRESP
	}
	return dst, nil
}

// InputStream is a helper type for managing input streams from inside
// the Data event.
type InputStream struct{ b []byte }

// Begin accepts a new packet and returns a working sequence of
// unprocessed bytes.
func (is *InputStream) Begin(packet []byte) (data []byte) {
	data = packet
	if len(is.b) > 0 {
		is.b = append(is.b, data...)
		data = is.b
	}
	return data
}

// End shifts the stream to match the unprocessed data.
func (is *InputStream) End(data []byte) {
	if len(data) > 0 {
		if len(data) != len(is.b) {
			is.b = append(is.b[:0], data...)
		}
	} else if len(is.b) > 0 {
		is.b = is.b[:0]
	}
}

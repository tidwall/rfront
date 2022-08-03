package main

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tidwall/redcon"
)

type proxyClient struct {
	req        *http.Request
	eof        bool
	hwr        http.ResponseWriter
	ws         *websocket.Conn
	rc         net.Conn
	rd         *bufio.Reader
	token      string
	conn       net.Conn      // for raw hijacked connection
	pktin      []byte        // for raw hijacked connection
	bufout     *bufio.Writer // for raw hijacked connection
	is         InputStream
	query      url.Values
	nspace     string
	acl        *aclMap
	acltok     *aclToken
	cluster    *clusterInfo
	cupdated   uint64
	namespaces *namespaceMap
}

func newClient(w http.ResponseWriter, r *http.Request, namespaces *namespaceMap,
) (*proxyClient, error) {
	q := r.URL.Query()
	var ws *websocket.Conn
	var conn net.Conn
	var err error
	if r.Header.Get("Connection") == "Upgrade" {
		switch r.Header.Get("Upgrade") {
		case "raw":
			conn, err = hijackRaw(w, r)
			if err != nil {
				return nil, err
			}
		default:
			// Assume websocket as default upgrade.
			// The upgrader will complete handshake.
			ws, err = upgrader.Upgrade(w, r, nil)
			if err != nil {
				return nil, err
			}
		}
	}
	pc := &proxyClient{
		req:        r,
		hwr:        w,
		ws:         ws,
		query:      q,
		conn:       conn,
		token:      getAuthToken(r.Header, q),
		namespaces: namespaces,
		nspace:     r.URL.Path[1:],
	}
	if pc.conn != nil {
		pc.pktin = make([]byte, 8192)
		pc.bufout = bufio.NewWriterSize(pc.conn, 8192)
	}
	return pc, nil
}

func getAuthToken(h http.Header, q url.Values) string {
	token := h.Get("Authorization")
	if token == "" {
		return q.Get("token")
	}
	if strings.HasPrefix(token, "token ") {
		return token[6:]
	}
	if strings.HasPrefix(token, "Basic ") {
		return token[6:]
	}
	if strings.HasPrefix(token, "Bearer ") {
		return token[7:]
	}
	return ""
}

func (pc *proxyClient) Close() {
	if pc.ws != nil {
		// websocket client
		pc.ws.Close()
	}
	if pc.conn != nil {
		// hijacked client
		pc.conn.Close()
	}
	if pc.rc != nil {
		// redis server
		pc.rc.Close()
	}
}

func (pc *proxyClient) readMessage() (data []byte, err error) {
	if pc.conn != nil {
		// Hijacked Connection
		n, err := pc.conn.Read(pc.pktin)
		if err != nil {
			return nil, err
		}
		data = pc.pktin[:n]
		return data, nil
	}

	if pc.ws != nil {
		// Websocket
		_, msg, err := pc.ws.ReadMessage()
		if err != nil {
			return nil, err
		}
		data = msg
	} else {
		// Plain HTTP
		if pc.eof {
			return nil, io.EOF
		}
		pc.eof = true
		qcmd := pc.query.Get("cmd")
		if qcmd != "" {
			data = []byte(qcmd)
		} else {
			var err error
			data, err = io.ReadAll(pc.req.Body)
			if err != nil {
				return nil, err
			}
		}
	}
	// Append an extra new line onto the tail of the packet to that plain
	// telnet-like commands can be sent over a websocket connection without
	// the need for adding the extra line breaks.
	data = append(data, '\r', '\n')
	return data, nil
}

func appendAutoJSON(dst []byte, resp redcon.RESP) []byte {
	switch resp.Type {
	case redcon.Array:
		dst = append(dst, '[')
		var i int
		resp.ForEach(func(resp redcon.RESP) bool {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendAutoJSON(dst, resp)
			i++
			return true
		})
		dst = append(dst, ']')
	}
	return dst
}

func (pc *proxyClient) writeMessage(msg []byte) error {
	if pc.conn != nil {
		// hijacked connection
		_, err := pc.bufout.Write(msg)
		return err
	}
	if pc.ws != nil {
		// websocket
		return pc.ws.WriteMessage(2, msg)
	}
	// plain HTTP request
	_, err := pc.hwr.Write(msg)
	return err
}

func (pc *proxyClient) flushWrite() error {
	if pc.conn != nil {
		// hijacked connection
		return pc.bufout.Flush()
	}
	return nil
}

func (pc *proxyClient) allow(commandName string) bool {
	if pc.acltok == nil || !pc.acltok.valid() {
		pc.acltok = nil
		_, pc.acl, _ = pc.namespaces.get(pc.nspace)
		if pc.acl == nil {
			return false
		}
		pc.acltok = pc.acl.auth(pc.token)
		if pc.acltok == nil {
			return false
		}
	}
	if pc.acltok.allow {
		if pc.acltok.except[commandName] {
			return false
		}
	} else {
		if !pc.acltok.except[commandName] {
			return false
		}
	}
	return true
}

func (pc *proxyClient) proxy() error {
	for {
		in, err := pc.readMessage()
		if err != nil {
			// network level error
			return err
		}
		data := pc.is.Begin(in)
		var complete bool
		var args [][]byte
		for {
			complete, args, _, data, err =
				redcon.ReadNextCommand(data, args[:0])
			if err != nil {
				return err
			}
			if !complete {
				break
			}
			if len(args) > 0 {
				sargs := make([]string, len(args))
				for i, arg := range args {
					sargs[i] = string(arg)
				}
				sargs[0] = strings.ToLower(sargs[0])
				if sargs[0] == "auth" {
					if len(sargs) != 2 {
						err = pc.writeMessage(
							[]byte("-ERR wrong number of arguments\r\n"))
					} else {
						if sargs[1] != pc.token {
							pc.token = sargs[1]
							if pc.acltok != nil {
								pc.acltok = nil
							}
						}
						err = pc.writeMessage([]byte("+OK\r\n"))
					}
				} else if !pc.allow(sargs[0]) {
					err = pc.writeMessage([]byte("-ERR unauthorized\r\n"))
				} else {
					err = pc.execCommand(sargs)
				}
				if err != nil {
					return err
				}
			}
			for len(data) >= 2 && string(data[:2]) == "\r\n" {
				data = data[2:]
			}
		}
		pc.is.End(data)
		if err := pc.flushWrite(); err != nil {
			return err
		}
	}
}

func (pc *proxyClient) ensureValidCluster() (updated bool, err error) {
	if pc.cluster != nil && pc.cluster.valid() {
		// Appears to be valid
		return false, nil
	}

	// The namespace cluster has been updated.
	// Close the client connection to the redis server and clone the
	// the updated cluster.
	pc.cluster = nil
	if pc.rc != nil {
		pc.rc.Close()
		pc.rc = nil
	}

	pc.cluster, _, _ = pc.namespaces.get(pc.nspace)
	if pc.cluster == nil {
		return false, errors.New("namespace not found")
	}
	pc.cluster = pc.cluster.copy()
	return true, nil
}

// execCommand will run a single command on the redis cluster
func (pc *proxyClient) execCommand(args []string) error {
	// Prepare the command for sending to the server
	cmdData := redcon.AppendArray(nil, len(args))
	for _, arg := range args {
		cmdData = redcon.AppendBulkString(cmdData, arg)
	}

	var ignoreAddr []string
	var usedAddr string
	var execOK bool
	defer func() {
		if execOK && usedAddr != "" && pc.cluster != nil {
			pc.cluster.leader.set(usedAddr)
		}
	}()

	var leaderAddr string

	// Attempt to write the command to the server.
	// Try for 15 seconds and then timeout.
	start := time.Now()
	for time.Since(start) < 15*time.Second {

		// ensure that the cluster is valid
		updated, err := pc.ensureValidCluster()
		if err != nil {
			log.Printf("ensure cluster: %s", err)
			return pc.writeMessage([]byte("-ERR unauthorized\r\n"))
		}
		if updated {
			leaderAddr = pc.cluster.leader.get()
		}

		var addr string
		if pc.rc == nil {
			// Client is not connected.
			// Attempt to connect to a server
			var err error
			if leaderAddr != "" {
				// A leader is recommended
				addr = leaderAddr
				leaderAddr = "" // do not reuse the same leader recommendation.
				pc.rc, err = net.Dial("tcp", addr)
			} else {
				for i := 0; i < len(pc.cluster.addrs); i++ {
					addr = pc.cluster.addrs[i]
					var ignore bool
					for _, addr2 := range ignoreAddr {
						if addr == addr2 {
							ignore = true
							break
						}
					}
					if ignore {
						continue
					}
					pc.rc, err = net.Dial("tcp", addr)
					if err == nil {
						break
					}
					time.Sleep(time.Millisecond * 250)
				}
			}
			if err != nil {
				// could not connect, sleep and try again
				ignoreAddr = append(ignoreAddr, addr)
				log.Printf("dial: %s", err)
				time.Sleep(time.Millisecond * 250)
				continue
			}
			if pc.rc == nil {
				// could not find a valid server to connect to.
				break
			}
			pc.rd = bufio.NewReader(pc.rc)
			if pc.cluster.auth != "" {
				auth := redcon.AppendArray(nil, 2)
				auth = redcon.AppendBulkString(auth, "AUTH")
				auth = redcon.AppendBulkString(auth, pc.cluster.auth)
				_, err := pc.rc.Write(auth)
				if err != nil {
					return err
				}
				resp, err := readRESP(nil, pc.rd)
				if err != nil {
					return err
				}
				if string(resp) != "+OK\r\n" {
					pc.rc.Close()
					pc.rc = nil
					return pc.writeMessage([]byte("-ERR unauthorized\r\n"))
				}
			}
		}

		// We are now connected to a server in the cluster.
		// Write the actual bytes to the server.
		if _, err := pc.rc.Write(cmdData); err != nil {
			// Error writing data, due to network issue, or the server
			// going down, etc.
			// Close the connection and try again.
			pc.rc.Close()
			pc.rc = nil
			continue
		}

		// Read the response.
		resp, err := readRESP(nil, pc.rd)
		if err != nil {
			if err == errInvalidRESP {
				// Invalid resp means that the redis server sent back that
				// contained invalid data.
				// Consider this broken and close the connection.
				pc.writeMessage([]byte("-ERR invalid internal response\r\n"))
				return err
			} else {
				// Error reading data, due to network issue, or the server
				// going down, etc.
				// Close the connection and try again.
				pc.rc.Close()
				pc.rc = nil
				continue
			}
		}
		if resp[0] == '-' {
			emsg := strings.TrimSpace(string(resp[1:]))
			if isLeadershipError(emsg) {
				// Leadership error is one that requires closing the connection
				// and attempting to reconnect to a valid leader.
				pc.rc.Close()
				pc.rc = nil
				if strings.HasPrefix(emsg, "TRY ") {
					leaderAddr = err.Error()[4:]
				} else if strings.HasPrefix(emsg, "MOVED ") {
					parts := strings.Split(emsg, " ")
					if len(parts) == 3 {
						leaderAddr = parts[2]
					}
				} else {
					// CLUSTERDOWN or a leadership change in progress.
					// Give a small delay and beore retrying
					time.Sleep(time.Millisecond * 250)
				}
				continue
			} else if strings.HasPrefix(emsg, "NOAUTH") {
				// Make error consistent
				resp = []byte("-ERR unauthorized\r\n")
			}
		}
		usedAddr = addr
		execOK = true
		return pc.writeMessage(resp)
	}
	return pc.writeMessage([]byte("-ERR connection timeout\r\n"))
}

// Copyright 2022 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package redfront

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tidwall/jsonc"
	"github.com/tidwall/redcon"
	"golang.org/x/crypto/acme/autocert"
)

type aclToken struct {
	allow  bool
	except map[string]bool
}

type config struct {
	Port    int      `json:"port"`
	Hosts   []string `json:"hosts"`
	Cluster struct {
		Addrs []string `json:"addrs"`
		Auth  string   `json:"auth"`
	} `json:"cluster"`
	ACL []struct {
		Tokens []string `json:"tokens"`
		Access string   `json:"access"`
		Except []string `json:"except"`
	} `json:"acl"`
	tokens map[string]*aclToken
}

func Main() {
	var path string
	flag.StringVar(&path, "config", "config.json", "Path to config file")
	flag.Parse()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	var cfg config
	if err := json.Unmarshal(jsonc.ToJSONInPlace(data), &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	cfg.tokens = make(map[string]*aclToken)
	for i, acl := range cfg.ACL {
		var allow bool
		switch acl.Access {
		case "allow":
			allow = true
		case "disallow":
			allow = false
		default:
			if acl.Access == "" {
				fmt.Fprintf(os.Stderr, "acl %d: missing kind\n", i)
			} else {
				fmt.Fprintf(os.Stderr, "acl %d: invalid kind: %s\n", i, acl.Access)
			}
			os.Exit(1)
		}
		acltok := aclToken{
			allow:  allow,
			except: make(map[string]bool),
		}
		for _, cmd := range acl.Except {
			acltok.except[strings.ToLower(cmd)] = true
		}
		for _, token := range acl.Tokens {
			cfg.tokens[token] = &acltok
		}
	}
	makeServer := func(addr string) *http.Server {
		return &http.Server{
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      &hserver{cfg: &cfg},
			Addr:         addr,
		}
	}
	if len(cfg.Hosts) > 0 {
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Hosts...),
			Cache:      autocert.DirCache("./certs"),
		}
		s := makeServer(":https")
		s.TLSConfig = &tls.Config{GetCertificate: mgr.GetCertificate}
		for _, host := range cfg.Hosts {
			log.Printf("Listening at https://%s", host)
		}
		go func() {
			// serve HTTP, which will redirect automatically to HTTPS
			h := mgr.HTTPHandler(nil)
			log.Fatal(http.ListenAndServe(":http", h))
		}()
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		log.Printf("Listening at http://0.0.0.0:%d", cfg.Port)
		s := makeServer(fmt.Sprintf(":%d", cfg.Port))
		log.Fatal(s.ListenAndServe())
	}
}

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
	case emsg == "ERR node is not the leader":
		return true
	case emsg == "ERR leadership lost while committing log":
		return true
	case emsg == "ERR leadership transfer in progress":
		return true
	}
	return false
}

var upgrader = websocket.Upgrader{} // use default options

type hserver struct {
	cfg *config
}

func (s *hserver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pc, err := newProxyClient(w, r, s.cfg)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer pc.Close()
	err = pc.Proxy()
	if err != nil {
		emsg := err.Error()
		if !strings.Contains(emsg, "websocket: close ") && emsg != "EOF" {
			log.Printf("proxy: %s", err)
		}
	}
}

type proxyClient struct {
	req     *http.Request
	eof     bool
	hwr     http.ResponseWriter
	ws      *websocket.Conn
	rc      net.Conn
	rd      *bufio.Reader
	query   url.Values
	cfg     *config
	acltok  *aclToken
	packet  []byte
	cluster []string
}

func newProxyClient(
	w http.ResponseWriter, r *http.Request, cfg *config,
) (*proxyClient, error) {
	q := r.URL.Query()
	auth := getAuth(r.Header, q)
	var ws *websocket.Conn
	if r.Header.Get("Connection") == "Upgrade" {
		var err error
		ws, err = upgrader.Upgrade(w, r, nil)
		if err != nil {
			return nil, err
		}
	}
	pc := &proxyClient{
		req:     r,
		hwr:     w,
		ws:      ws,
		query:   q,
		acltok:  cfg.tokens[auth],
		cfg:     cfg,
		cluster: append([]string{}, cfg.Cluster.Addrs...),
	}
	return pc, nil
}

func getAuth(h http.Header, q url.Values) string {
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

func (pc *proxyClient) shuffleCluster() {
	rand.Shuffle(len(pc.cluster), func(i, j int) {
		pc.cluster[i], pc.cluster[j] = pc.cluster[j], pc.cluster[i]
	})
}

func (pc *proxyClient) Close() {
	if pc.ws != nil {
		pc.ws.Close()
	}
	if pc.rc != nil {
		pc.rc.Close()
	}
}

func (pc *proxyClient) readMessage() error {
	if pc.ws == nil {
		// Plain HTTP
		if pc.eof {
			return io.EOF
		}
		pc.eof = true
		qcmd := pc.query.Get("cmd")
		if qcmd != "" {
			pc.packet = []byte(qcmd)
		} else {
			var err error
			pc.packet, err = io.ReadAll(pc.req.Body)
			if err != nil {
				return err
			}
		}
	} else {
		// Websocket
		_, msg, err := pc.ws.ReadMessage()
		if err != nil {
			return err
		}
		pc.packet = append(pc.packet, msg...)
	}
	// Append an extra new line onto the tail of the packet to that plain
	// telnet-like commands can be sent over a websocket connection without
	// the need for adding the extra line breaks.
	pc.packet = append(pc.packet, '\r', '\n')
	return nil
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
	if pc.ws == nil {
		_, err := pc.hwr.Write(msg)
		return err
	} else {
		return pc.ws.WriteMessage(2, msg)
	}
}

func (pc *proxyClient) allow(commandName string) bool {
	commandName = strings.ToLower(commandName)
	if pc.acltok == nil || commandName == "auth" {
		return false
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

func (pc *proxyClient) Proxy() error {
	if pc.acltok == nil {
		// unauthorized and quit
		if pc.ws == nil {
			pc.hwr.WriteHeader(http.StatusUnauthorized)
		}
		return pc.writeMessage([]byte("-ERR unauthorized\r\n"))
	}
	for {
		if err := pc.readMessage(); err != nil {
			// network level error
			return err
		}
		for {
			complete, args, _, leftover, err :=
				redcon.ReadNextCommand(pc.packet, nil)
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

				if !pc.allow(sargs[0]) {
					err = pc.writeMessage([]byte("-ERR unauthorized\r\n"))
				} else {
					err = pc.execCommand(sargs)
				}
				if err != nil {
					return err
				}
			}
			for len(leftover) >= 2 && string(leftover[:2]) == "\r\n" {
				leftover = leftover[2:]
			}
			pc.packet = append(pc.packet[:0], leftover...)
		}
	}
}

// execCommand will run a single command on the redis cluster
func (pc *proxyClient) execCommand(args []string) error {
	// Prepare the command for sending to the server
	cmdData := redcon.AppendArray(nil, len(args))
	for _, arg := range args {
		cmdData = redcon.AppendBulkString(cmdData, arg)
	}

	var leaderAddr string

	// Attempt to write the command to the server.
	// Try for 5 seconds and then timeout.
	writeTimeout := time.Second * 5
	start := time.Now()
	for time.Since(start) < writeTimeout {
		if pc.rc == nil {
			// Connect to a redis server
			var err error
			if leaderAddr != "" {
				pc.rc, err = net.Dial("tcp", leaderAddr)
				leaderAddr = "" // do not reuse the same leader
			} else {
				pc.shuffleCluster()
				for _, addr := range pc.cluster {
					pc.rc, err = net.Dial("tcp", addr)
					if err == nil {
						break
					}
				}
				if pc.rc == nil && err == nil {
					pc.writeMessage([]byte("-ERR no servers available\r\n"))
					return errors.New("no servers available")
				}
			}
			if err != nil {
				// could not connect, sleep and try again
				log.Printf("dial: %s", err)
				time.Sleep(time.Millisecond * 250)
				continue
			}
			pc.rd = bufio.NewReader(pc.rc)

			if pc.cfg.Cluster.Auth != "" {
				auth := redcon.AppendArray(nil, 2)
				auth = redcon.AppendBulkString(auth, "AUTH")
				auth = redcon.AppendBulkString(auth, pc.cfg.Cluster.Auth)
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
		_, err := pc.rc.Write(cmdData)
		if err != nil {
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
			}
		}
		return pc.writeMessage(resp)
	}
	return pc.writeMessage([]byte("-ERR connection timeout\r\n"))
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

// Copyright 2022 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/websocket"
	"github.com/tidwall/jsonc"
	"github.com/tidwall/redcon"
	"golang.org/x/crypto/acme/autocert"
)

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
}

func jsonEquals(a, b interface{}) bool {
	data1, err := json.Marshal(a)
	if err != nil {
		return false
	}
	data2, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(data1, data2)
}

type clusterInfo struct {
	mu      sync.RWMutex
	updated uint64
	addrs   []string
	auth    string
	parent  *clusterInfo
}

func (cluster *clusterInfo) update(cfg *config) error {
	cluster.mu.Lock()
	cluster.updated++
	cluster.addrs = append([]string{}, cfg.Cluster.Addrs...)
	cluster.auth = cfg.Cluster.Auth
	cluster.mu.Unlock()
	return nil
}

func (cluster *clusterInfo) copy() *clusterInfo {
	cluster.mu.RLock()
	copy := &clusterInfo{
		updated: cluster.updated,
		addrs:   cluster.addrs,
		auth:    cluster.auth,
		parent:  cluster,
	}
	cluster.mu.RUnlock()
	return copy
}

func (cluster *clusterInfo) valid() bool {
	var valid bool
	cluster.mu.RLock()
	if cluster.parent != nil {
		cluster.parent.mu.RLock()
		valid = cluster.parent.updated == cluster.updated
		cluster.parent.mu.RUnlock()
	}
	cluster.mu.RUnlock()
	return valid
}

type aclToken struct {
	invalid int32 // atomic: bool
	allow   bool
	except  map[string]bool
}

func (acltok *aclToken) valid() bool {
	return atomic.LoadInt32(&acltok.invalid) == 0
}
func (acltok *aclToken) invalidate() {
	atomic.StoreInt32(&acltok.invalid, 1)
}

type aclMap struct {
	mu     sync.RWMutex
	tokens map[string]*aclToken
}

func (acl *aclMap) auth(token string) *aclToken {
	acl.mu.RLock()
	defer acl.mu.RUnlock()
	return acl.tokens[token]
}

func (acl *aclMap) update(cfg *config) error {
	tokens := make(map[string]*aclToken)
	for i, acl := range cfg.ACL {
		var allow bool
		switch acl.Access {
		case "allow":
			allow = true
		case "disallow":
			allow = false
		default:
			if acl.Access == "" {
				return fmt.Errorf("%d: missing kind\n", i)
			}
			return fmt.Errorf("%d: invalid kind: %s\n", i, acl.Access)
		}
		acltok := aclToken{
			allow:  allow,
			except: make(map[string]bool),
		}
		for _, cmd := range acl.Except {
			acltok.except[strings.ToLower(cmd)] = true
		}
		for _, token := range acl.Tokens {
			tokens[token] = &acltok
		}
	}
	// all is good, update acl now.
	acl.mu.Lock()
	oldtoks := acl.tokens
	acl.tokens = tokens
	acl.mu.Unlock()

	// invalid old tokens, this will cause the connected users
	for _, acltok := range oldtoks {
		acltok.invalidate()
	}
	return nil
}

func readConfig(path string) (config, error) {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(jsonc.ToJSONInPlace(data), &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func followChanges(path string, cfg config, acl *aclMap, cluster *clusterInfo) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for e := range w.Events {
			if e.Op != fsnotify.Write {
				continue
			}
			// An event changed in the
			cfg2, err := readConfig(path)
			if err != nil {
				log.Printf("%s", err)
				continue
			}
			if !jsonEquals(cfg2, cfg) {
				// configuration has changed.
				if !jsonEquals(cfg2.ACL, cfg.ACL) {
					if err := acl.update(&cfg2); err != nil {
						log.Printf("acl: %s", err)
					} else {
						log.Printf("acl: updated")
					}
				}
				if !jsonEquals(cfg2.Cluster, cfg.Cluster) {
					if err := cluster.update(&cfg2); err != nil {
						log.Printf("cluster: %s", err)
					} else {
						log.Printf("cluster: updated")
					}
				}
				if !jsonEquals(cfg2.Hosts, cfg.Hosts) ||
					!jsonEquals(cfg2.Port, cfg.Port) {
					log.Printf("server: updated (requires restarting program)")
				}
				cfg = cfg2
			}
		}
	}()
	if err := w.Add(filepath.Dir(path)); err != nil {
		log.Fatal(err)
	}
}

func main() {
	var path string
	flag.StringVar(&path, "config", "config.json", "Path to config file")
	flag.Parse()

	log.SetFlags(0)
	cfg, err := readConfig(path)
	if err != nil {
		log.Fatal(err)
	}

	var cluster clusterInfo
	if err := cluster.update(&cfg); err != nil {
		log.Fatal(err)
	}

	var acl aclMap
	if err := acl.update(&cfg); err != nil {
		log.Fatal(err)
	}

	handler := &serverHandler{
		acl:     &acl,
		cluster: &cluster,
	}

	makeServer := func(addr string) *http.Server {
		return &http.Server{
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      handler,
			Addr:         addr,
		}
	}

	followChanges(path, cfg, &acl, &cluster)

	var s1 *http.Server
	var s2 *http.Server
	hosts := cfg.Hosts
	port := cfg.Port
	for {

		if len(hosts) > 0 {
			mgr := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(hosts...),
				Cache:      autocert.DirCache("./certs"),
			}
			s1 = &http.Server{Addr: ":http", Handler: mgr.HTTPHandler(nil)}
			s2 = makeServer(":https")
			s2.TLSConfig = &tls.Config{GetCertificate: mgr.GetCertificate}
			ln1, err := net.Listen("tcp", s1.Addr)
			if err != nil {
				log.Fatal(err)
			}
			ln2, err := net.Listen("tcp", s2.Addr)
			if err != nil {
				log.Fatal(err)
			}
			for _, host := range hosts {
				log.Printf("Listening at https://%s", host)
			}
			go func() {
				log.Fatal(s1.Serve(ln1))
			}()
			log.Fatal(s2.ServeTLS(ln2, "", ""))
		} else {
			s1 = makeServer(fmt.Sprintf(":%d", port))
			ln, err := net.Listen("tcp", s1.Addr)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Listening at http://0.0.0.0:%d", port)
			log.Fatal(s1.Serve(ln))
		}
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

var upgrader = websocket.Upgrader{} // use default options

type serverHandler struct {
	acl     *aclMap
	cluster *clusterInfo
}

func (s *serverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pc, err := newProxyClient(w, r, s.acl, s.cluster)
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

func hijack(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
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

type proxyClient struct {
	req      *http.Request
	eof      bool
	hwr      http.ResponseWriter
	ws       *websocket.Conn
	rc       net.Conn
	rd       *bufio.Reader
	token    string
	conn     net.Conn
	query    url.Values
	acl      *aclMap
	acltok   *aclToken
	packet   []byte
	cluster  *clusterInfo
	cupdated uint64
}

func newProxyClient(
	w http.ResponseWriter, r *http.Request,
	acl *aclMap, cluster *clusterInfo,
) (*proxyClient, error) {
	q := r.URL.Query()
	var ws *websocket.Conn
	var conn net.Conn
	var err error
	if r.Header.Get("Connection") == "Upgrade" {
		switch r.Header.Get("Upgrade") {
		case "hijack":
			conn, err = hijack(w, r)
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
		req:     r,
		hwr:     w,
		ws:      ws,
		query:   q,
		conn:    conn,
		acl:     acl,
		token:   getAuthToken(r.Header, q),
		cluster: cluster.copy(),
	}
	return pc, nil
}

func (pc *proxyClient) shuffleCluster() {
	addrs := pc.cluster.addrs
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})
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
	if pc.acltok == nil || !pc.acltok.valid() {
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

func (pc *proxyClient) Proxy() error {
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
				sargs[0] = strings.ToLower(sargs[0])

				if sargs[0] == "auth" {
					if len(sargs) != 2 {
						err = pc.writeMessage(
							[]byte("-ERR wrong number of arguments\r\n"))
					} else {
						pc.token = sargs[1]
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

		if !pc.cluster.valid() {
			// The share cluster has been updated.
			// Close the client connection to the redis server and clone the
			// the updated cluster.
			if pc.rc != nil {
				pc.rc.Close()
				pc.rc = nil
			}
			pc.cluster = pc.cluster.parent.copy()
		}

		if pc.rc == nil {
			// Connect to a redis server
			var err error
			if leaderAddr != "" {
				pc.rc, err = net.Dial("tcp", leaderAddr)
				leaderAddr = "" // do not reuse the same leader
			} else {
				pc.shuffleCluster()
				for _, addr := range pc.cluster.addrs {
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
			} else if strings.HasPrefix(emsg, "NOAUTH") {
				// Make error consistent
				resp = []byte("-ERR unauthorized\r\n")
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
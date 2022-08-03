// Copyright 2022 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	var path string
	flag.StringVar(&path, "config", "config.json", "Path to config file")
	flag.Parse()

	log.SetFlags(0)
	namespaces := &namespaceMap{
		namespaces: make(map[string]*namespaceInfo),
	}
	cfg, err := loadConfigAndFollowChanges(path, namespaces)
	if err != nil {
		log.Fatal(err)
	}

	handler := &server{
		namespaces: namespaces,
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

var upgrader = websocket.Upgrader{} // use default options

type server struct {
	namespaces *namespaceMap
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pc, err := newClient(w, r, s.namespaces)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer pc.Close()
	err = pc.proxy()
	if err != nil {
		emsg := err.Error()
		if !strings.Contains(emsg, "websocket: close ") && emsg != "EOF" {
			log.Printf("proxy: %s", err)
		}
	}
}

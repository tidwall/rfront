package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

type namespaceInfo struct {
	mu      sync.RWMutex
	cluster *clusterInfo
	acl     *aclMap
}

type namespaceMap struct {
	mu         sync.RWMutex
	namespaces map[string]*namespaceInfo
}

func (nmap *namespaceMap) get(nspace string) (*clusterInfo, *aclMap, bool) {
	nmap.mu.RLock()
	defer nmap.mu.RUnlock()
	ninfo, ok := nmap.namespaces[nspace]
	if !ok {
		return nil, nil, false
	}
	return ninfo.cluster, ninfo.acl, true
}

func (nmap *namespaceMap) set(nspace string,
	cluster *clusterInfo, acl *aclMap,
) bool {
	nmap.mu.Lock()
	defer nmap.mu.Unlock()
	ninfo, ok := nmap.namespaces[nspace]
	if !ok {
		ninfo = &namespaceInfo{}
		nmap.namespaces[nspace] = ninfo
	}
	ninfo.cluster = cluster
	ninfo.acl = acl
	return ok
}

func (nmap *namespaceMap) delete(names ...string) {
	var infos []*namespaceInfo

	// delete namespaces so new connections cannot use.
	nmap.mu.Lock()
	for _, name := range names {
		ninfo, ok := nmap.namespaces[name]
		if ok {
			infos = append(infos, ninfo)
			delete(nmap.namespaces, name)
		}
	}
	nmap.mu.Unlock()

	// invalid old namespace info so existing connections stop using.
	for _, ninfo := range infos {

		for _, acltok := range ninfo.acl.tokens {
			acltok.invalidate()
		}
		ninfo.cluster.mu.Lock()
		ninfo.cluster.updated++
		ninfo.cluster.mu.Unlock()
	}
}

type leaderAddr struct {
	mu   sync.RWMutex
	addr string
}

func (la *leaderAddr) get() string {
	la.mu.RLock()
	addr := la.addr
	la.mu.RUnlock()
	return addr
}
func (la *leaderAddr) set(addr string) {
	la.mu.Lock()
	la.addr = addr
	la.mu.Unlock()
}

type clusterInfo struct {
	mu      sync.RWMutex
	updated uint64
	addrs   []string
	leader  *leaderAddr // leader address, atomic
	auth    string
	parent  *clusterInfo
}

func (cluster *clusterInfo) update(cfg *configCluster) error {
	cluster.mu.Lock()
	cluster.updated++
	cluster.addrs = append([]string{}, cfg.Addrs...)
	cluster.auth = cfg.Auth
	cluster.mu.Unlock()
	return nil
}

func (cluster *clusterInfo) copy() *clusterInfo {
	cluster.mu.RLock()
	copy := &clusterInfo{
		updated: cluster.updated,
		leader:  cluster.leader,
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

func (acl *aclMap) update(cfg *[]configACL) error {
	tokens := make(map[string]*aclToken)
	for i, acl := range *cfg {
		var allow bool
		switch acl.Access {
		case "allow":
			allow = true
		case "disallow":
			allow = false
		default:
			if acl.Access == "" {
				return fmt.Errorf("acl %d: missing kind\n", i)
			}
			return fmt.Errorf("acl %d: invalid kind: %s\n", i, acl.Access)
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

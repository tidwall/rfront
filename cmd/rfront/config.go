package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/tidwall/gjson"
	"github.com/tidwall/jsonc"
)

type configCluster struct {
	Addrs []string `json:"addrs"`
	Auth  string   `json:"auth"`
}

type configACL struct {
	Tokens []string `json:"tokens"`
	Access string   `json:"access"`
	Except []string `json:"except"`
}

type configNamespace struct {
	Cluster configCluster `json:"cluster"`
	ACL     []configACL   `json:"acl"`
}

type config struct {
	Port       int                        `json:"port"`
	Hosts      []string                   `json:"hosts"`
	Namespaces map[string]configNamespace `json:"namespaces"`
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

func readConfig(path string) (cfg config, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	data = jsonc.ToJSONInPlace(data)
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	// Load root-level namespace
	var defnspace configNamespace
	vcluster := gjson.GetBytes(data, "cluster")
	vacl := gjson.GetBytes(data, "acl")
	if vcluster.Exists() || vacl.Exists() {
		if _, ok := cfg.Namespaces[""]; ok {
			return cfg, errors.New("Ambiguous default namespace. " +
				"Cannot have both root-level 'cluster' and 'acl' fields and " +
				"a default namespace at the same time.")
		}
		if err := json.Unmarshal(data, &defnspace); err != nil {
			return cfg, err
		}
		if cfg.Namespaces == nil {
			cfg.Namespaces = make(map[string]configNamespace)
		}
		cfg.Namespaces[""] = defnspace
	}
	return cfg, nil
}

// loadConfigAndFollowChanges loads the configuration file and continues to
// monitor and updates the systems when changes happen.
func loadConfigAndFollowChanges(path string, namespace *namespaceMap) (
	config, error,
) {
	var ferr error
	var fcfg config
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fcfg, err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		ferr = w.Add(filepath.Dir(path))
		wg.Done()
		if ferr != nil {
			wg.Done()
			return
		}

		var once bool   // for first run detection
		var lcfg config // last known config

		for {
			if once {
				for {
					e := <-w.Events
					if e.Op == fsnotify.Write {
						break
					}
				}
			}
			// An event changed in the
			cfg2, err := readConfig(path)
			if err != nil {
				if !once {
					ferr = err
					wg.Done()
					return
				} else {
					log.Printf("%s", err)
				}
				continue
			}

			if !once || !jsonEquals(cfg2, lcfg) {
				// A change to the configurate has occurred.
				if !once || !jsonEquals(cfg2.Hosts, lcfg.Hosts) ||
					!jsonEquals(cfg2.Port, lcfg.Port) {
					// cannot dyanically update Hosts or Port
					if once {
						log.Printf(
							"server: updated (requires restarting program)")
					}
				}
				// Update all new/existing namespaces
				for name, ncfg := range cfg2.Namespaces {
					lncfg, lnok := lcfg.Namespaces[name]
					cluster, acl, exists := namespace.get(name)
					if cluster == nil {
						cluster = &clusterInfo{
							leader: new(leaderAddr),
						}
					}
					if acl == nil {
						acl = new(aclMap)
					}
					var clusterUpdated bool
					var aclUpdated bool
					err := func() error {
						var err error
						if !once || !jsonEquals(ncfg.Cluster, lncfg.Cluster) {
							err = cluster.update(&ncfg.Cluster)
							if err != nil {
								return err
							}
							clusterUpdated = true
						}
						if !once || !jsonEquals(ncfg.ACL, lncfg.ACL) {
							err = acl.update(&ncfg.ACL)
							if err != nil {
								return err
							}
							aclUpdated = true
						}
						return nil
					}()
					if err != nil {
						err = fmt.Errorf("namespace '%s': %s", name, err)
						if !once {
							ferr = err
							wg.Done()
							return
						} else {
							log.Printf("%s", err)
						}
					}
					if !exists {
						namespace.set(name, cluster, acl)
					}
					if once {
						if !lnok {
							log.Printf("namespace '%s': added", name)
						} else {
							if clusterUpdated {
								log.Printf("namespace '%s': cluster updated",
									name)
							}
							if aclUpdated {
								log.Printf("namespace '%s': acl updated", name)
							}
						}
					}
				}

				// delete removed namespaces
				var deletedNames []string
				for name := range lcfg.Namespaces {
					_, ok := cfg2.Namespaces[name]
					if !ok {
						deletedNames = append(deletedNames, name)
					}
				}
				namespace.delete(deletedNames...)
				for _, name := range deletedNames {
					log.Printf("namespace '%s': deleted", name)
				}

				lcfg = cfg2
			}
			if !once {
				once = true
				fcfg = lcfg
				wg.Done()
			}
		}
	}()

	wg.Wait()
	return fcfg, ferr
}

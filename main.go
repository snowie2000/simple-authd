// simple-authd project main.go
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

type stringList map[string]string

func (l *stringList) String() string {
	return fmt.Sprintln(*l)
}
func (l *stringList) Set(value string) error {
	kv := strings.SplitN(value, ":", 2)
	if len(kv) == 2 {
		(*l)[kv[0]] = kv[1]
	}
	return nil
}

var (
	userlist   stringList = make(stringList)
	timeout    int
	listen     string
	tokenCache sync.Map
)

func newToken() string {
	p := make([]byte, 16)
	rand.Read(p)
	phex := hex.EncodeToString(p)
	tokenCache.Store(phex, time.Now().Add(time.Second*time.Duration(timeout)))
	return phex
}

func paw() {
	var t time.Time
	for {
		time.Sleep(time.Minute * 5)
		t = time.Now()
		tokenCache.Range(func(key, value interface{}) bool {
			if value.(time.Time).Before(t) {
				tokenCache.Delete(key)
			}
			return true
		})
	}
}

func serveAuth(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if c, err := r.Cookie("pvtoken"); err == nil {
		if _, ok := tokenCache.Load(c.Value); ok {
			w.WriteHeader(http.StatusOK)
		}
	}
	basicAuthPrefix := "Basic "
	// get request header
	auth := r.Header.Get("Authorization")
	// http basic auth
	if strings.HasPrefix(auth, basicAuthPrefix) {
		// decode auth info
		payload, err := base64.StdEncoding.DecodeString(
			auth[len(basicAuthPrefix):],
		)
		if err == nil {
			pair := strings.SplitN(string(payload), ":", 2)
			if len(pair) == 2 {
				if pwd, ok := userlist[pair[0]]; ok && pwd == pair[1] {
					// success!
					log.Println(pair[0], "authorized")
					w.Header().Set("Set-Cookie", fmt.Sprintf("pvtoken=%s; Max-Age=%d;", newToken(), timeout))
					w.WriteHeader(http.StatusOK)
					return
				} else {
					log.Println(pair[0], "failed with password", pair[1])
				}
			}
		}
	}
	// return 401 Unauthorized with realm Restricted.
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func main() {
	flag.Var(&userlist, "u", "username:password pairs. can be called multiple times.")
	flag.IntVar(&timeout, "t", 3600, "token timeout, in second")
	flag.StringVar(&listen, "l", "127.0.0.1:3333", "bind address")
	flag.Parse()
	if len(userlist) == 0 {
		flag.PrintDefaults()
		return
	}
	rand.Seed(time.Now().UnixNano())
	go paw()
	if err := http.ListenAndServe(listen, http.HandlerFunc(serveAuth)); err != nil {
		log.Fatalln(err)
	}
}

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/oshynsong/netunnel"
	"github.com/oshynsong/netunnel/statics"
)

const tokenHeaderKey = "X-Net-Token"

func createWebappMux(user, pass string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", webappAuthMiddleware(user, pass, webappMainHandler))
	mux.HandleFunc("/favicon.ico", webappFaviconHandler)
	mux.HandleFunc("/sw.js", webappServiceWorkerHandler)
	mux.HandleFunc("/forward/", webappForwardHandler)
	return mux
}

func webappAuthMiddleware(user, pass string, next http.HandlerFunc) http.HandlerFunc {
	expUserHash := sha256.Sum256([]byte(user))
	expPassHash := sha256.Sum256([]byte(pass))
	return func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		return

		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			userMatch := subtle.ConstantTimeCompare(expUserHash[:], usernameHash[:])
			passMatch := subtle.ConstantTimeCompare(expPassHash[:], passwordHash[:])
			if userMatch == 1 && passMatch == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted", charset="UTF-8"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
}

func webappMainHandler(w http.ResponseWriter, r *http.Request) {
	index, err := statics.Get("main.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		netunnel.LogError(r.Context(), "can't load index.html: %w", err)
		return
	}

	buf := make([]byte, 16)
	if n, e := rand.Read(buf); e != nil || n != len(buf) {
		w.WriteHeader(http.StatusInternalServerError)
		netunnel.LogError(r.Context(), "create server rand key failed: %w", err)
		return
	}
	tokenCookie := &http.Cookie{
		Name:     tokenHeaderKey,
		Value:    hex.EncodeToString(buf),
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Set-Cookie", tokenCookie.String())
	if _, err = w.Write(index); err != nil {
		netunnel.LogError(r.Context(), "write index.html failed: %w", err)
	}
}

func webappFaviconHandler(w http.ResponseWriter, r *http.Request) {
	ico, err := statics.Get("app.ico")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		netunnel.LogError(r.Context(), "can't load app.ico: %w", err)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	if _, err = w.Write(ico); err != nil {
		netunnel.LogError(r.Context(), "write app.ico failed: %w", err)
	}
}

var (
	sessionKeyMap  = make(map[string]string) // ip => sessionKey
	sessionKeyLock = new(sync.RWMutex)
)

func webappServiceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	netunnel.LogInfo(r.Context(), "handle service worker register: %s", r.URL)
	var err error
	var body []byte
	defer func() {
		if err != nil {
			netunnel.LogError(r.Context(), "service worker handler failed: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err = w.Write(body); err != nil {
			netunnel.LogError(r.Context(), "write sw.js failed: %w", err)
		}
	}()

	// Get the server random key from cookie, which set by the index handler.
	var serverToken *http.Cookie
	serverToken, err = r.Cookie(tokenHeaderKey)
	if err != nil || serverToken == nil || len(serverToken.Value) == 0 {
		err = fmt.Errorf("get server token key failed: %w", err)
		return
	}
	netunnel.LogInfo(r.Context(), "got server token key: %s", serverToken.Value)

	// Get the client random token to generate the session token.
	clientToken := r.URL.Query().Get("token")
	if len(clientToken) == 0 {
		err = fmt.Errorf("client token key not given")
		return
	}
	netunnel.LogInfo(r.Context(), "got client token key: %s", clientToken)
	sessionKey := sha256.Sum256([]byte(serverToken.Value + clientToken))
	remoteAddr, addrErr := netip.ParseAddrPort(r.RemoteAddr)
	if addrErr != nil {
		err = fmt.Errorf("parse remote addr failed: %w", addrErr)
		return
	}
	sessionKeyLock.Lock()
	sessionKeyMap[remoteAddr.Addr().String()] = string(sessionKey[:])
	sessionKeyLock.Unlock()
	netunnel.LogInfo(r.Context(), "generate session key %x for client: %s", sessionKey, remoteAddr)

	// Return the service worker module.
	body, err = statics.Get("sw.js")
	if err != nil {
		err = fmt.Errorf("can't load sw.js: %w", err)
		return
	}
	w.Header().Set("Content-Type", "text/javascript")
}

func webappForwardHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	var addr string
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			netunnel.LogError(r.Context(), "forward request %s failed: %v", addr, err)
		}
	}()

	// Proxy the request to the real server side.
	addr = r.URL.Query().Get("addr")
	path := strings.TrimPrefix(r.URL.Path, "/forward")
	var proxyReq *http.Request
	addr = strings.TrimSuffix(addr, "/") + "/" + strings.TrimPrefix(path, "/")
	addr = strings.TrimSuffix(addr, "/")
	up, upErr := url.Parse(addr)
	if upErr != nil {
		err = fmt.Errorf("parse forward url failed: %w", upErr)
		return
	}
	if len(up.Scheme) == 0 {
		up.Scheme = "http"
	}
	addr = up.String()
	proxyReq, err = http.NewRequest(r.Method, up.String(), r.Body)
	if err != nil {
		err = fmt.Errorf("create proxy request failed: %w", err)
		return
	}
	var proxyResp *http.Response
	proxyResp, err = http.DefaultClient.Do(proxyReq)
	if err != nil {
		err = fmt.Errorf("send proxy request failed: %w", err)
		return
	}
	respBody, _ := io.ReadAll(proxyResp.Body)
	// reg := regexp.MustCompile(`((https?:)?//([\w_-]+\.)+[\w_-]+/?)([A-Za-z0-9./!@#$%&?=\-_;]*)`)
	// body = reg.ReplaceAll(respBody, []byte(`/forward/$4?addr=$1`))
	w.WriteHeader(proxyResp.StatusCode)
	// w.Header().Set("Content-Type", proxyResp.Header.Get("Content-Type"))
	if _, err = w.Write(respBody); err != nil {
		netunnel.LogError(r.Context(), "forward write response failed: %w", err)
	} else {
		netunnel.LogInfo(r.Context(), "forward request %s success", addr)
	}
}

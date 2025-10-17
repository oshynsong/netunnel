package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/oshynsong/netunnel"
	"github.com/oshynsong/netunnel/statics"
)

const tokenHeaderKey = "X-Net-Token"

func createWebappMux(user, pass string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", webappAuthMiddleware(user, pass, webappIndexHandler))
	mux.HandleFunc("/favicon.ico", webappFaviconHandler)
	mux.HandleFunc("/api/ws", webappWSHandler)
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

func webappIndexHandler(w http.ResponseWriter, r *http.Request) {
	index, err := statics.Get("index.html")
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

var webappHandshake = websocket.Upgrader{
	HandshakeTimeout: time.Second,
	ReadBufferSize:   8 * 1024,
	WriteBufferSize:  8 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header["Origin"]
		if len(origin) == 0 {
			netunnel.LogError(r.Context(), "missing origin header")
			return false
		}
		u, err := url.Parse(origin[0])
		if err != nil {
			netunnel.LogError(r.Context(), "origin header %v parse failed: %v", origin[0], err)
			return false
		}
		if !strings.EqualFold(u.Host, r.Host) {
			netunnel.LogError(r.Context(), "origin header %s not equal request host %v", u.Host, r.Host)
			return false
		}
		return true
	},
	EnableCompression: true,
}

func webappWSHandler(w http.ResponseWriter, r *http.Request) {
	// Get the server random key from cookie, which set by the index handler.
	serverToken, err := r.Cookie(tokenHeaderKey)
	if err != nil || serverToken == nil || len(serverToken.Value) == 0 {
		netunnel.LogError(r.Context(), "get server token key failed: %w", err)
		return
	}
	netunnel.LogInfo(r.Context(), "got server token key: %s", serverToken.Value)

	// Get the client random key to generate the session token.
	clientToken, addr := r.URL.Query().Get("key"), r.URL.Query().Get("addr")
	if len(clientToken) == 0 || len(addr) == 0 {
		netunnel.LogError(r.Context(), "client token key or addr invalid")
		return
	}
	sessionKey := sha256.Sum256([]byte(serverToken.Value + clientToken))
	netunnel.LogInfo(r.Context(), "got client token=%s addr=%s sessionKey=%x", clientToken, addr, sessionKey)

	// Perform the websocket handshake.
	conn, connErr := webappHandshake.Upgrade(w, r, nil)
	if connErr != nil {
		netunnel.LogError(r.Context(), "websocket upgrade failed: %v", connErr)
		return
	}
	defer conn.Close()

	/*var lastPingWrite time.Time
	go func() {
		pingInterval := time.Second * 5
		t := time.NewTimer(pingInterval)
		defer t.Stop()
		for {
			select {
			case c := <-t.C:
				if err := conn.WriteMessage(websocket.PingMessage, []byte("PING")); err != nil {
					netunnel.LogError(r.Context(), "websocket ping failed: %v", err)
					return
				}
				atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&lastPingWrite)), unsafe.Pointer(&c))
			}
		}
	}()
	*/

	resp, err := http.DefaultClient.Get(addr)
	if err != nil {
		netunnel.LogError(r.Context(), "websocket GET failed: %v", err)
		return
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	if err = conn.WriteMessage(websocket.TextMessage, bodyBytes); err != nil {
		netunnel.LogError(r.Context(), "websocket write failed: %v", err)
	}
	for {
		msgType, msg, msgErr := conn.ReadMessage()
		if msgErr != nil {
			netunnel.LogError(r.Context(), "websocket read message failed: %v", msgErr)
			return
		}
		netunnel.LogInfo(r.Context(), "websocket read message: type=%v msg=%v", msgType, string(msg))

		if msgErr = conn.WriteMessage(msgType, msg); msgErr != nil {
			netunnel.LogError(r.Context(), "websocket write message failed: %v", msgErr)
			return
		}
	}
}

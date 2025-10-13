package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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

func webappWSHandler(w http.ResponseWriter, r *http.Request) {
	// Get the server random key from cookie, which set by the index handler.
	serverToken, err := r.Cookie(tokenHeaderKey)
	if err != nil || serverToken == nil || len(serverToken.Value) == 0 {
		netunnel.LogError(r.Context(), "get server token key failed: %w", err)
		return
	}
	netunnel.LogInfo(r.Context(), "got server token key: %s", serverToken.Value)

	// Get the client random key to generate the session token.
	protocols := websocket.Subprotocols(r)
	if len(protocols) != 2 {
		netunnel.LogError(r.Context(), "client token key invalid: %v", protocols)
		return
	}
	addr, clientToken := protocols[0], protocols[1]
	netunnel.LogInfo(r.Context(), "got client tokenKey=%s addr=%s", clientToken, addr)

	// sessionKey := sha256.Sum256([]byte(serverToken.Value + clientToken))
	respHeader := make(http.Header)
	/*tokenCookie := &http.Cookie{
		Name:     tokenHeaderKey,
		Value:    hex.EncodeToString(sessionKey[:]),
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   true,
	}
	respHeader.Set("Set-Cookie", tokenCookie.String())*/

	// Perform the websocket handshake.
	var handshakeHandler = websocket.Upgrader{
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
		Subprotocols:      protocols, // must return the same sub protocols to the client
	}
	conn, connErr := handshakeHandler.Upgrade(w, r, respHeader)
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

	for {
		if err := conn.WriteControl(websocket.PingMessage, []byte("PING"), time.Now().Add(time.Second)); err != nil {
			netunnel.LogError(r.Context(), "websocket ping failed: %v", err)
			return
		}
		netunnel.LogInfo(r.Context(), "websocket send pong")

		msgType, msg, msgErr := conn.ReadMessage()
		if msgErr != nil {
			netunnel.LogError(r.Context(), "websocket read message failed: %v", msgErr)
			return
		}
		netunnel.LogInfo(r.Context(), "websocket read message: type=%v msg=%v", msgType, string(msg))
		/*if msgType == websocket.PongMessage {
			now := time.Now()
			atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&lastPingWrite)), unsafe.Pointer(&now))
		}
		*/

		/*if msgErr = conn.WriteMessage(msgType, msg); msgErr != nil {
			netunnel.LogError(r.Context(), "websocket write message failed: %v", msgErr)
			return
		}

		*/
	}
}

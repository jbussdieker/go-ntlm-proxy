package main

import "github.com/ThomsonReutersEikon/go-ntlm/ntlm"

import (
  "flag"
  "log"
  "net/http"
  "strings"
  "unicode"
  "encoding/binary"
  "encoding/base64"
)

var (
  listen   = flag.String("listen", "localhost:1080", "listen on address")
  user     = flag.String("user", "user", "NTLM user we expect")
  password = flag.String("password", "password", "NTLM password we expect")
  domain   = flag.String("domain", "domain", "NTLM domain we expect")
  logp     = flag.Bool("log", false, "enable logging")
)

var session ntlm.ServerSession

func main() {
  flag.Parse()
  proxyHandler := http.HandlerFunc(proxyHandlerFunc)
  log.Fatal(http.ListenAndServe(*listen, proxyHandler))
}

func proxyHandlerFunc(w http.ResponseWriter, r *http.Request) {
  // Make sure there is some kind of authentication
  if r.Header.Get("Proxy-Authorization") == "" {
    log.Println("No authentication detected")
    w.Header().Set("Proxy-Authenticate", "NTLM")
    w.WriteHeader(407)
    return
  }

  // Parse the proxy authorization header
  proxy_auth := r.Header.Get("Proxy-Authorization")
  parts := strings.SplitN(proxy_auth, " ", 2)
  proxy_auth_type := parts[0]
  proxy_auth_payload := parts[1]

  // Filter out unsupported authentication methods
  if proxy_auth_type != "NTLM" {
    log.Println("Unsupported " + proxy_auth_type + " authentication detected")
    w.Header().Set("Proxy-Authenticate", "NTLM")
    w.WriteHeader(407)
    return
  }

  // Decode base64 auth data and get NTLM message type
  raw_proxy_auth_payload, _ := base64.StdEncoding.DecodeString(proxy_auth_payload)
  ntlm_message_type := binary.LittleEndian.Uint32(raw_proxy_auth_payload[8:12])

  // Handle NTLM negotiate message
  if ntlm_message_type == 1 {
    log.Println("NTLM Negotiate message received")

    session, _ = ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
    session.SetUserInfo(*user, *password, *domain)
    challenge, _ := session.GenerateChallengeMessage()
    proxy_auth_payload := base64.StdEncoding.EncodeToString(challenge.Bytes())

    log.Println("NTLM Challenge message sent")
    w.Header().Set("Proxy-Authenticate", "NTLM " + proxy_auth_payload)
    w.WriteHeader(407)

    return
  }

  if ntlm_message_type == 3 {
    log.Println("NTLM Challenge response received")

    authenticate_message, err := ntlm.ParseAuthenticateMessage(raw_proxy_auth_payload, 1)

    // TODO: Figure out why we can't make a real session
    session, _ = ntlm.CreateServerSession(ntlm.Version1, ntlm.ConnectionOrientedMode)
    err = session.ProcessAuthenticateMessage(authenticate_message)
    if err != nil {
      log.Println(err)
      w.Header().Set("Proxy-Authenticate", "NTLM")
      w.WriteHeader(407)
      return
    }
  }

  if *logp {
    log.Println(r.URL)
  }

  // We'll want to use a new client for every request.
  client := &http.Client{}

  // Tweak the request as appropriate:
  //  RequestURI may not be sent to client
  //  URL.Scheme must be lower-case
  r.RequestURI = ""
  r.URL.Scheme = strings.Map(unicode.ToLower, r.URL.Scheme)

  // And proxy
  resp, err := client.Do(r)
  if err != nil {
    log.Fatal(err)
  }

  resp.Write(w)
}

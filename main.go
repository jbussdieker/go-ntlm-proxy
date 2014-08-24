package main

import "github.com/ThomsonReutersEikon/go-ntlm/ntlm"
import l4g "github.com/ThomsonReutersEikon/log4go"

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
  listen   = flag.String("listen", "localhost:8080", "listen on address")
  user     = flag.String("user", "user", "NTLM user we expect")
  password = flag.String("password", "password", "NTLM password we expect")
  domain   = flag.String("domain", "domain", "NTLM domain we expect")
)

var challenges map[string]*ntlm.ChallengeMessage

func main() {
  flag.Parse()

  // Just ignore internal messages from ntlm lib for now
  l4g.Close()

  challenges = make(map[string]*ntlm.ChallengeMessage)

  proxyHandler := http.HandlerFunc(proxyHandlerFunc)
  log.Fatal(http.ListenAndServe(*listen, proxyHandler))
}

func proxyHandlerFunc(w http.ResponseWriter, r *http.Request) {
  var err error

  // Make sure there is some kind of authentication
  if r.Header.Get("Proxy-Authorization") == "" {
    log.Println(r.RemoteAddr, "ERROR: No authentication detected")
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
    log.Println(r.RemoteAddr, "Unsupported " + proxy_auth_type + " authentication detected")
    w.Header().Set("Proxy-Authenticate", "NTLM")
    w.WriteHeader(407)
    return
  }

  // Decode base64 auth data and get NTLM message type
  raw_proxy_auth_payload, _ := base64.StdEncoding.DecodeString(proxy_auth_payload)
  ntlm_message_type := binary.LittleEndian.Uint32(raw_proxy_auth_payload[8:12])

  // Handle NTLM negotiate message
  if ntlm_message_type == 1 {
    log.Println(r.RemoteAddr, "NTLM Negotiate message received")

    session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
    if err != nil {
      log.Println(r.RemoteAddr, "Error with CreateServerSession:", err)
      return
    }

    session.SetUserInfo(*user, *password, *domain)

    challenge, err := session.GenerateChallengeMessage()
    if err != nil {
      log.Println(r.RemoteAddr, "Error with GenerateChallengeMessage:", err)
      return
    }

    challenges[r.RemoteAddr] = challenge

    proxy_auth_payload := base64.StdEncoding.EncodeToString(challenge.Bytes())

    log.Println(r.RemoteAddr, "NTLM Challenge message sent")
    w.Header().Set("Proxy-Authenticate", "NTLM " + proxy_auth_payload)
    w.WriteHeader(407)

    return
  }

  if ntlm_message_type == 3 {
    log.Println(r.RemoteAddr, "NTLM Challenge response received")

    challenge := challenges[r.RemoteAddr]
    if challenge == nil {
      log.Println(r.RemoteAddr, "ERROR: Challenge response when no challenge was sent")
      w.Header().Set("Proxy-Authenticate", "NTLM")
      w.WriteHeader(407)
      return
    }

    msg, err := ntlm.ParseAuthenticateMessage(raw_proxy_auth_payload, 2)
    if err != nil {
      msg2, err := ntlm.ParseAuthenticateMessage(raw_proxy_auth_payload, 1)

      if err != nil {
        log.Println(r.RemoteAddr, "Error with ParseAuthenticateMessage:", err)
        return
      }

      session, err := ntlm.CreateServerSession(ntlm.Version1, ntlm.ConnectionOrientedMode)
      if err != nil {
        log.Println(r.RemoteAddr, "Error with CreateServerSession:", err)
        return
      }

      session.SetServerChallenge(challenge.ServerChallenge)
      session.SetUserInfo(*user, *password, *domain)

      err = session.ProcessAuthenticateMessage(msg2)
      if err != nil {
        log.Println(r.RemoteAddr, "NTLM Authentication Failed:", err)
        w.Header().Set("Proxy-Authenticate", "NTLM")
        w.WriteHeader(407)
        return
      }
    } else {
      session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
      if err != nil {
        log.Println(r.RemoteAddr, "Error with CreateServerSession:", err)
        return
      }

      session.SetServerChallenge(challenge.ServerChallenge)
      session.SetUserInfo(*user, *password, *domain)

      err = session.ProcessAuthenticateMessage(msg)
      if err != nil {
        log.Println(r.RemoteAddr, "ERROR:", err)
        w.Header().Set("Proxy-Authenticate", "NTLM")
        w.WriteHeader(407)
        return
      }
    }
  }

  log.Println(r.RemoteAddr, "Downstream request ", r.Method, r.URL)

  // Transform request
  r.RequestURI = ""
  r.URL.Scheme = strings.Map(unicode.ToLower, r.URL.Scheme)
  r.Header.Del("Proxy-Connection")
  r.Header.Del("Proxy-Authorization")

  log.Println(r.RemoteAddr, "Upstream request   ", r.Method, r.URL)

  // Fetch upstream
  client := &http.Client{}
  resp, err := client.Do(r)
  if err != nil {
    log.Fatal(err)
  }

  log.Println(r.RemoteAddr, "Upstream response  ", resp.Proto, resp.Status)

  hj, ok := w.(http.Hijacker)
  if !ok {
    http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
    return
  }

  // Hijack the response writer
  conn, bufrw, err := hj.Hijack()
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  // Don't forget to close the connection:
  defer conn.Close()

  log.Println(r.RemoteAddr, "Downstream response", resp.Proto, resp.Status)

  // Write downstream response
  resp.Write(bufrw)
  bufrw.Flush()
}

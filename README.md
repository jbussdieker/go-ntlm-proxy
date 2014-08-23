# Simple HTTP Proxy with NTLM Auth

    $ go run main.go -log

    $ curl http://google.com -x http://localhost:1080 -U "domain/user:password" --proxy-ntlm

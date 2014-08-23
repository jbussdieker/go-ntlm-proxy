# Simple HTTP Proxy with NTLM Auth

    $ go run main.go

    $ curl -x localhost:8080 --proxy-ntlm -U domain/user:password http://google.com

# go-radius

[![GoDoc](https://godoc.org/github.com/blind-oracle/go-radius?status.svg)](https://godoc.org/github.com/blind-oracle/go-radius)

It's quite heavily rewritten fork of another Go [RADIUS library](https://github.com/layeh/radius)

Significant changes are:
* Common
  * Encoding/Decoding of attribute 26 (Vendor-Specific)
  * RFC2866 & RFC2869 (Accounting)

* Server
  * Request throttling (maximum requests per second) support
  * Supports limiting the number of requests in processing queue
  * Multiple RADIUS Secrets based on packet's source IP with a fallback default
  * Request/Response packet replication (useful for logging, IDS etc)
  * Configurable UDP buffer size

* Client
  * Lots of vendor-specific (Cisco, Juniper, Mikrotik) functions and constants
  * Support for generating CoA/Disconnect-Message packets

## Installation
    go get -u github.com/blind-oracle/go-radius

## Server example
```go
import (
    "github.com/blind-oracle/go-radius"
    "log"
)

func main() {
    handler := func (w radius.ResponseWriter, p *radius.Packet) {
        w.AccessAccept()
    }

    server := radius.Server{
        Addr:           "0.0.0.0:1812",
        Handler:        radius.HandlerFunc(handler),
        Secret:         []byte(o.RADIUSSecret),
        Dictionary:     radius.Builtin,
    }

    if err := server.ListenAndServe(); err != nil {
        log.Fatal(err)
    }
}
```

## Client example
```go
import (
    "github.com/blind-oracle/go-radius"
    "log"
)

func main() {
    client := radius.Client{}
    packet := radius.New(radius.CodeAccessRequest, []byte("VerySecret"))
    packet.Add("Calling-Station-Id", "NAS-Fake")

    reply, err := client.Exchange(packet, "1.2.3.4:1812")
    if err != nil {
        log.Fatalf(err)
    }

    switch reply.Code {
        case radius.CodeAccessAccept:
        log.Println("Accept")
        case radius.CodeAccessReject:
        log.Println("Reject")
    }
}
```

## Authors
* Tim Cooper (<tim.cooper@layeh.com>)
* Igor Novgorodov (<igor@novg.net>)

# go-radius

It's a fork of a nice Go RADIUS library: https://github.com/layeh/radius

Significant changes:
* Common
** Encoding/Decoding of attribute 26 (Vendor-Specific)
** RFC2866 & RFC2869 (Accounting)
** RFC5176

* Server
** Request throttling (maximum requests per second) support
** Supports limiting the number of requests in processing queue
** Multiple RADIUS Secrets based on packet's source IP with a fallback default
** Request/Response packet replication (useful for logging etc)
** Configurable UDP buffer size

* Client
** Vendor-specific (Cisco, Juniper, Mikrotik) functions and constants


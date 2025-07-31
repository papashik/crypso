# crypso
[![Go Reference](https://pkg.go.dev/badge/pkg/go/dev/github.com/papashik/crypso.svg)](https://pkg.go.dev/github.com/papashik/crypso)

This module provides utility for generating `x509` certificates, using fork of official `crypto/x509` library. It adds `MLDSA-65` algorithm (one of `MLDSA Dilithium` family from [Cloudflare source](github.com/cloudflare/circl/sign/mldsa/mldsa65)) support for private keys (see [README.md](x509/README.md)).

New `x509` library with `MLDSA-65` support can be imported as
```go
import "github.com/papashik/crypso/x509"
```

## Usage
**Note:** `crypso` is a symlink for compiled application, for testing use `go run .` instead.
### Help
```bash
crypso --help
```

When used in any mode, use `-v` or `-vv` to see detailed logs.

### Generate example
```bash
crypso gen -v --ca-private=ca-private.pem --ca-cert=ca.pem --ca-algorithm=MLDSA65 --ca-name=CA_ORG --ca-start="2025-01-01" \
--private=private.pem --cert=cert.pem --algorithm=MLDSA65 --name="ORG" --start="2025-01-01" --hosts=localhost,1.1.1.1
```

```
INFO    Generated private key   {"path": "private.pem", "algorithm": "MLDSA65"}
INFO    Generated private key   {"path": "ca-private.pem", "algorithm": "MLDSA65"}
INFO    Generated certificate   {"path": "ca.pem"}
INFO    Generated certificate   {"path": "cert.pem"}
```
### Verify example
```bash
crypso -v verify cert.pem ca.pem
```
```
INFO    Read certificate from file      {"path": "cert.pem", "algorithm": "MLDSA65"}
INFO    Read certificate from file      {"path": "ca.pem", "algorithm": "MLDSA65"}
INFO    Successfully verified
```
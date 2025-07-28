# crypso

## Help
```bash
go run . --help
```

When used in any mode, use `-v` or `-vv` to see detailed logs.

## Generate
```bash
go run . gen --ca-private=ca-private.pem --ca-cert=ca.pem --ca-algorithm=MLDSA65 --ca-name=CA_ORG --ca-start "2025-01-01" \
 --private=private.pem --cert=cert.pem --algorithm=ECDSA --name "ORG" --start "2025-01-01" --hosts=localhost,1.1.1.1
```
At this moment, generating CA certificate fails with ECDSA or RSA algorithm.
## Verify
```bash
go run . verify cert.pem ca.pem  -vv
```

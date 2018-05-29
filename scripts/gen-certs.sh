#!/bin/bash -e

mkdir -p assets

cfssl gencert -initca examples/tls/ca.json | cfssljson -bare assets/ca
cfssl gencert -ca=assets/ca.pem -ca-key=assets/ca-key.pem \
    -config=examples/tls/config.json -profile=server -hostname="localhost" \
    examples/tls/server.json | cfssljson -bare assets/server



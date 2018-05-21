#!/bin/bash -e

mkdir profiles

echo '{
  "signing": {
    "default": {
      "expiry": "876000h"
    },
    "profiles": {
      "server": {
        "expiry": "876000h",
        "usages": ["signing", "key encipherment", "server auth"]
      },
      "client": {
        "expiry": "876000h",
        "usages": ["signing", "key encipherment", "client auth"]
      }
    }
  }
}' > profiles/config.json
echo '{"CN":"etcd-ca","key":{"algo":"ecdsa","size":256}}' > profiles/ca.json
echo '{"CN":"root","key":{"algo":"ecdsa","size":256}}' > profiles/client.json
echo '{"CN":"etcd-server","key":{"algo":"ecdsa","size":256}}' > profiles/server.json

cfssl gencert -initca profiles/ca.json | cfssljson -bare ca

cfssl gencert -ca=ca.pem -ca-key=ca-key.pem \
    -config=profiles/config.json -profile=client \
    profiles/client.json | cfssljson -bare client

cfssl gencert -ca=ca.pem -ca-key=ca-key.pem \
    -config=profiles/config.json -profile=server -hostname="localhost" \
    profiles/server.json | cfssljson -bare server

rm -rf profiles
rm *.csr

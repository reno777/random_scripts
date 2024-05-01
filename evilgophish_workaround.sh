#!/bin/bash
# Install go 
wget https://go.dev/dl/go1.20.6.linux-amd64.tar.gz 
sha256sum go1.20.6.linux-amd64.tar.gz 
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.6.linux-amd64.tar.gz 
ln -sf /usr/local/go/bin/go /usr/bin/go 
go version
 
# Download working version of evilgophish (gophish + evilginx2) 
wget https://github.com/fin3ss3g0d/evilgophish/archive/abdbe59a6f0c7e32bf0065980d553a5a5fb37924.zip 
unzip abdbe59a6f0c7e32bf0065980d553a5a5fb37924.zip

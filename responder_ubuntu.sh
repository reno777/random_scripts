#!/bin/bash
apt update
apt upgrade -y
sh -c "echo 'deb https://http.kali.org/kali kali-rolling main non-free contrib' > /etc/apt/sources.list.d/kali.list"
apt update
apt install gnupg -y
wget 'https://archive.kali.org/archive-key.asc'
apt-key add archive-key.asc
apt update
apt install responder

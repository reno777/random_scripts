#!/bin/bash
RED=$'\033[0;31m'
NC=$'\033[0m'
DOMAIN="replace with domain"
apt install unzip -y
cd /opt
mkdir gophish
cd gophish
wget https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip
unzip gophish-v0.11.0-linux-64bit.zip
chmod 744 gophish
snap install --classic certbot
while true; do
        read -p  "${RED}[!!!]${NC} Have you configured the DNS settings in godaddy for $DOMAIN, www.$DOMAIN, mail.$DOMAIN, and login.microsoftonline.$DOMAIN? To continue press Y or y." yn
        case $yn in
                [Yy]* ) break;;
                [Nn]* ) echo -e "${RED}Please do so before continuing.${NC}";;
                * ) echo -e "${RED}Please do so before continuing.${NC}";;
        esac
done
certbot certonly --standalone --expand -d $DOMAIN -d www.$DOMAIN -d mail.$DOMAIN -d login.microsoftonline.$DOMAIN -n --register-unsafely-without-email --agree-tos
export GOPHISH_INITIAL_ADMIN_PASSWORD=gophish
sed -i "s:gophish_admin.crt:/etc/letsencrypt/live/$DOMAIN/fullchain.pem:" config.json
sed -i "s:gophish_admin.key:/etc/letsencrypt/live/$DOMAIN/privkey.pem:" config.json
sed -i "s:example.crt:/etc/letsencrypt/live/$DOMAIN/fullchain.pem:" config.json
sed -i "s:example.key:/etc/letsencrypt/live/$DOMAIN/privkey.pem:" config.json
sed -i 's/false/true/' config.json
sed -i 's/80/443/' config.json
tmux new-session -d -s gophish 'cd /opt/gophish; ./gophish'

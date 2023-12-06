#!/bin/bash

RED=$'\033[0;31m'
NC=$'\033[0m'
read -p 'New Client Name: ' cname
cap="$(tr '[:lower:]' '[:upper:]' <<< ${cname:0:1})${cname:1}"
cd ~/Documents/engagements/
mkdir -p $cname/{ext/{forced_auth,harvest,nmap,pwspray},int,prereqs,reciepts,reports/{deliverables/nessus,final,initial},screenshots,se}
cp ~/Documents/engagements/resources/passwords-all.txt $cname/ext/pwspray/.
echo "${RED}[!!!]${NC} New testing directory created at ~/Documents/engagements/"$cname"."
cd ~/Library/Mobile\ Documents/iCloud~md~obsidian/Documents/0xreno\ Notes/Work/
cp Template.md $cap.md
sed -i '' -e "s/Client/$cap/g" "$cap.md"
echo "${RED}[!!!]${NC} A new note has been created in Obsidian."

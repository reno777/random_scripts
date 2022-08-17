#!/bin/bash

read -p 'New Client Name: ' testvar
cd ~/Documents/engagements/
mkdir -p $testvar/{ext/{forced_auth,harvest,nmap},int,prereqs,reciepts,reports/{deliverables/nessus,final,initial},screenshots,se}
echo 'New testing directory created at ~/Documents/engagements/' $testvar

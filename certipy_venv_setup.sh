#!/bin/bash

git clone https://github.com/ly4k/Certipy.git 
cd Certipy
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
pip3 install .
pip3 install ldap3-bleeding-edge
deactivate
source .venv/bin/activate

#!/bin/bash

git clone https://github.com/dirkjanm/BloodHound.py.git
cd BloodHound.py
git switch bloodhound-ce
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
pip3 install .
pip3 install ldap3-bleeding-edge
deactivate
source .venv/bin/activate
bloodhound-ce-python

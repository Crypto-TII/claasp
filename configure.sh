#!/bin/bash

apt-get -qq update
apt-get install -y python3
python3 create_bash_script.py
./dependencies_script.sh
source ~/.bashrc
rm dependencies_script.sh
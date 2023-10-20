#!/bin/bash

apt-get -qq update
apt-get install -y python3
python3 create_bash_script.py $1
chmod +x dependencies_script.sh
./dependencies_script.sh
source ~/.bashrc
rm dependencies_script.sh
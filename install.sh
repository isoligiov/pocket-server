#!/bin/zsh

cd "$(dirname "$0")";

python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt

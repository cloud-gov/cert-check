#!/bin/sh

set -e

check_path=$(dirname $0)
pip3 install -r ${check_path}/requirements.txt

python3 -m certcheck

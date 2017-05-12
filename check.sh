#!/bin/sh

set -e

cd $(dirname $0)

pip3 install -r requirements.txt

python3 -m certcheck

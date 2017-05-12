#!/bin/sh

set -e

export PYTHONPATH=$(dirname $0)
pip3 install -r ${PYTHONPATH}/requirements.txt

python3 -m certcheck

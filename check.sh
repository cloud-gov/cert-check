#!/bin/sh

set -e

check_path=$(dirname $0)
pip3 install -r ${check_path}/requirements.txt

if [ -n "${BOSH_USERNAME:-}" ]; then
  bosh-cli log-in <<EOF 1>/dev/null
${BOSH_USERNAME}
${BOSH_PASSWORD}


EOF
fi

${check_path}/certificate-check.py

#!/bin/bash
# Container entrypoint. Usage: start.sh <role> [default-gateway]
set -e
role=$1 gw=${2:-}

if [ -n "$gw" ]; then ip route replace default via "$gw"; fi

case $role in
  fw-*)
    mkdir -p /var/log/fw /etc/lab
    cp /lab/$role/* /etc/lab/                    # working copy; faults edit this
    cp /lab/common/charon-logging.conf /etc/strongswan.d/charon-logging.conf
    ip route replace default dev wan             # the "ISP" is directly on wan
    nft -f /etc/lab/nftables.nft
    ulogd -d -c /lab/common/ulogd.conf
    /usr/lib/strongswan/charon >/var/log/fw/charon-stdout.log 2>&1 &
    for _ in $(seq 1 20); do swanctl --stats >/dev/null 2>&1 && break; sleep 0.5; done
    swanctl --load-all --file /etc/lab/swanctl.conf 2>&1 | grep -v "opening directory" >/dev/null || true
    ;;
  web:*)
    name=${role#web:}
    printf 'server { listen 80; location / { return 200 "%s\\n"; } }\n' "$name" \
      > /etc/nginx/http.d/default.conf
    nginx
    ;;
esac
exec sleep infinity

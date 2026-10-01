FROM docker.io/library/alpine:3.22
RUN apk add --no-cache nftables strongswan ulogd ulogd-json tcpdump curl nginx iperf3 \
        iputils nmap nmap-scripts conntrack-tools iproute2 bash rsyslog

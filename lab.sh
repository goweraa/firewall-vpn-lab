#!/usr/bin/env bash
# Firewall + site-to-site VPN troubleshooting lab (nftables + strongSwan
# IPsec) on isolated podman networks. Break things on purpose, then find the
# cause from rule counters, logs, packet captures and IKE logs.
set -euo pipefail

LAB="$(cd "$(dirname "$0")" && pwd)"
STATE="$LAB/logs/.fault"

#            name        subnet          (bridge gateway, unused by the lab)
NETWORKS=("wan          203.0.113.0/24  203.0.113.254"
          "lan-hq       10.10.1.0/24    10.10.1.254"
          "dmz-hq       10.10.3.0/24    10.10.3.254"
          "lan-branch   10.10.2.0/24    10.10.2.254")

FAULTS=(rule-order port-forward no-masquerade nat-exemption ike-proposal psk
        traffic-selector dmz-exposed)

ticket() {
  case $1 in
    rule-order)       echo "Since last night's change window, HQ users can't open the branch intranet app or plain-HTTP websites. Ping to the branch still works." ;;
    port-forward)     echo "Customers report the HQ public website is down from the internet. The web server team says the server is healthy." ;;
    no-masquerade)    echo "HQ users can't reach any internet website. The branch VPN works fine." ;;
    nat-exemption)    echo "The VPN to the branch shows as up, but HQ users can't reach anything at the branch. Internet access is fine." ;;
    ike-proposal)     echo "The branch VPN dropped after the branch firewall was 'hardened' by a contractor. Nothing at the branch is reachable from HQ." ;;
    psk)              echo "After a scheduled key rotation the branch VPN won't come up." ;;
    traffic-selector) echo "The branch VPN negotiates but HQ still can't reach the branch servers. Someone edited the branch firewall config." ;;
    dmz-exposed)      echo "Security audit finding: the DMZ web server may be able to reach internal HQ hosts. Verify and fix." ;;
  esac
}

c() { podman exec "$@"; }   # run in a container

net_up() {
  for n in "${NETWORKS[@]}"; do
    read -r name subnet gw <<<"$n"
    podman network exists "$name" ||
      podman network create --internal --subnet "$subnet" --gateway "$gw" "$name" >/dev/null
  done
}

# start <name> <caps> <role> <gateway|-> <network specs...>
start() {
  local name=$1 caps=$2 role=$3 gw=$4; shift 4
  local nets=() extra=()
  for n in "$@"; do nets+=(--network "$n"); done
  [[ $name == fw-* ]] && extra=(--sysctl net.ipv4.ip_forward=1 -v "$LAB/logs/$name:/var/log/fw:z")
  [[ $gw == - ]] && gw=""
  podman run -d --name "$name" --hostname "$name" --cap-add "$caps" "${extra[@]}" "${nets[@]}" \
    -v "$LAB:/lab:ro,z" fwlab /lab/common/start.sh "$role" $gw >/dev/null
}

up() {
  podman image exists fwlab || podman build -q -t fwlab "$LAB" >/dev/null
  net_up
  mkdir -p "$LAB/logs/fw-hq" "$LAB/logs/fw-branch"
  podman container exists fw-hq && { echo "Lab already up."; return; }
  local fw=NET_ADMIN,NET_RAW
  start fw-hq     $fw fw-hq      -  wan:ip=203.0.113.10,interface_name=wan \
                                    lan-hq:ip=10.10.1.1,interface_name=lan \
                                    dmz-hq:ip=10.10.3.1,interface_name=dmz
  start fw-branch $fw fw-branch  -  wan:ip=203.0.113.20,interface_name=wan \
                                    lan-branch:ip=10.10.2.1,interface_name=lan
  start hq-pc         $fw idle               10.10.1.1 lan-hq:ip=10.10.1.10
  start web-dmz       $fw web:hq-public-web  10.10.3.1 dmz-hq:ip=10.10.3.10
  start branch-srv    $fw web:branch-app     10.10.2.1 lan-branch:ip=10.10.2.10
  start internet-site $fw web:internet-site  -         wan:ip=203.0.113.50
  start attacker      $fw idle               -         wan:ip=203.0.113.66
  # The attacker tries to reach HQ's private ranges through the HQ firewall.
  sleep 2
  c attacker ip route add 10.10.0.0/16 via 203.0.113.10
  rm -f "$STATE"
  cat <<EOF
Lab up.
  HQ firewall      fw-hq       wan 203.0.113.10  lan 10.10.1.1  dmz 10.10.3.1
  Branch firewall  fw-branch   wan 203.0.113.20  lan 10.10.2.1
  HQ PC            hq-pc       10.10.1.10
  HQ public web    web-dmz     10.10.3.10  (published as 203.0.113.10:80)
  Branch app       branch-srv  10.10.2.10
  Internet site    internet-site 203.0.113.50
  Attacker         attacker    203.0.113.66
Run: $0 check
EOF
}

down() {
  podman rm -f -t0 fw-hq fw-branch hq-pc web-dmz branch-srv internet-site attacker >/dev/null 2>&1 || true
  for n in "${NETWORKS[@]}"; do read -r name _ <<<"$n"; podman network rm "$name" >/dev/null 2>&1 || true; done
  rm -f "$STATE"
  echo "Lab stopped (logs kept in logs/)."
}

# test <description> <expect: ok|blocked> <container> <command...>
pass=0 fail=0
t() {
  local desc=$1 expect=$2 ctr=$3; shift 3
  local got=blocked
  c "$ctr" sh -c "$*" >/dev/null 2>&1 && got=ok
  if [[ $got == "$expect" ]]; then
    printf '  PASS  %-45s (%s, as expected)\n' "$desc" "$got"; pass=$((pass + 1))
  else
    printf '  FAIL  %-45s (got %s, expected %s)\n' "$desc" "$got" "$expect"; fail=$((fail + 1))
  fi
}

check() {
  echo "Connectivity check"
  t "HQ PC -> internet website (outbound NAT)"  ok      hq-pc         "curl -sf -m4 http://203.0.113.50"
  t "HQ PC -> branch app (through VPN)"         ok      hq-pc         "curl -sf -m8 --retry 1 http://10.10.2.10"
  t "Branch server -> HQ PC (through VPN)"      ok      branch-srv    "ping -c2 -W2 10.10.1.10"
  t "Internet -> HQ public web (port forward)"  ok      internet-site "curl -sf -m4 http://203.0.113.10"
  t "Attacker -> HQ PC directly"                blocked attacker      "ping -c2 -W2 10.10.1.10"
  t "DMZ web server -> HQ PC (segmentation)"    blocked web-dmz       "ping -c2 -W2 10.10.1.10"
  echo
  echo "VPN state on fw-hq:"
  c fw-hq swanctl --list-sas 2>/dev/null | grep -E "ESTABLISHED|INSTALLED|bytes_i|in .*bytes" | sed 's/^/  /' ||
    echo "  no IKE/IPsec SAs"
  echo
  echo "$pass passed, $fail failed."
  [[ -f $STATE ]] && echo "A fault is active. Fix it, then run check again. ('$0 reveal' shows the answer.)"
  return 0
}

# Edit the working config inside a firewall and reload it.
fw_edit()   { c "$1" sed -i "$2" "/etc/lab/$3"; }
fw_reload() { c "$1" nft -f /etc/lab/nftables.nft; }
vpn_reload() {
  for fw in fw-hq fw-branch; do
    # swanctl looks for certificate folders this PSK lab doesn't use; hide that noise
    c $fw swanctl --load-all --clear --file /etc/lab/swanctl.conf 2>&1 | grep -v "opening directory" >/dev/null || true
  done
  c fw-hq swanctl --terminate --ike hq-branch --force >/dev/null 2>&1 || true
  c fw-branch swanctl --terminate --ike branch-hq --force >/dev/null 2>&1 || true
}

apply_fault() {
  case $1 in
    rule-order)
      fw_edit fw-hq '/# Site-to-site VPN/i\    iifname "lan" tcp dport 80 log prefix "FW-POLICY-BLOCK " group 1 drop comment "CHG-1042 block clear-text HTTP"' nftables.nft
      fw_reload fw-hq ;;
    port-forward)
      fw_edit fw-hq 's/dnat to \$WEB:80/dnat to 10.10.3.11:80/' nftables.nft; fw_reload fw-hq ;;
    no-masquerade)
      fw_edit fw-hq '/masquerade comment/d' nftables.nft; fw_reload fw-hq ;;
    nat-exemption)
      fw_edit fw-hq '/NAT exemption/d' nftables.nft; fw_reload fw-hq ;;
    ike-proposal)
      fw_edit fw-branch 's/proposals = aes256-sha256-modp2048 /proposals = aes128-sha1-modp1024 /' swanctl.conf; vpn_reload ;;
    psk)
      fw_edit fw-branch 's/lab-psk-Kr4k0w-2026/lab-psk-Kr4k0w-2027/' swanctl.conf; vpn_reload ;;
    traffic-selector)
      fw_edit fw-branch 's|remote_ts = 10.10.1.0/24|remote_ts = 10.10.11.0/24|' swanctl.conf; vpn_reload ;;
    dmz-exposed)
      fw_edit fw-hq '/log prefix "FW-FWD-DROP "/i\    iifname "dmz" accept comment "TEMP vendor troubleshooting - remove after ticket 5531"' nftables.nft
      fw_reload fw-hq ;;
    *) echo "Unknown fault: $1 (try: $0 faults)" >&2; exit 1 ;;
  esac
}

break_it() {
  local f=$1
  [[ -f $STATE ]] && { echo "A fault is already active. Run '$0 reset' first." >&2; exit 1; }
  if [[ $f == random ]]; then f=${FAULTS[RANDOM % ${#FAULTS[@]}]}; fi
  apply_fault "$f"
  echo "$f" > "$STATE"
  echo "Ticket: $(ticket "$f")"
  [[ $1 == random ]] && echo "(Fault hidden. '$0 reveal' shows which one.)"
  return 0
}

reset() {
  for fw in fw-hq fw-branch; do
    c $fw sh -c 'cp /lab/'$fw'/* /etc/lab/ && nft -f /etc/lab/nftables.nft'
  done
  vpn_reload
  rm -f "$STATE"
  echo "Both firewalls restored to the known-good config."
}

attack() {
  case ${1:-scan} in
    scan)
      echo "Attacker 203.0.113.66: TCP SYN scan of the HQ firewall, then a sweep of HQ's LAN"
      c attacker nmap -Pn -sS -T4 --top-ports 100 203.0.113.10 2>/dev/null | grep -E "open|filtered|Nmap done" | head -8
      c attacker nmap -Pn -sS -T4 -p 22,80,443,445,3389 10.10.1.0/28 2>/dev/null | tail -1
      echo "Now investigate logs/fw-hq/firewall.log" ;;
    *) echo "usage: $0 attack scan" >&2; exit 1 ;;
  esac
}

case ${1:-help} in
  up) up ;;
  down) down ;;
  check) check ;;
  faults) for f in "${FAULTS[@]}"; do printf '  %-17s %s\n' "$f" "$(ticket "$f")"; done ;;
  break) [[ $# -ge 2 ]] || { echo "usage: $0 break <fault>|random" >&2; exit 1; }; break_it "$2" ;;
  reveal) [[ -f $STATE ]] && echo "Active fault: $(cat "$STATE") (see SOLUTIONS.md)" || echo "No fault active." ;;
  reset) reset ;;
  attack) attack "${2:-scan}" ;;
  sh) [[ $# -ge 2 ]] || { echo "usage: $0 sh <container>" >&2; exit 1; }; podman exec -it "$2" bash ;;
  *) cat <<EOF
usage: $0 up | down | check | faults | break <fault>|random | reveal | reset | attack scan | sh <container>
EOF
  ;;
esac

# Firewall and site-to-site VPN troubleshooting lab

A self-contained network-security lab for practising what a SOC / network
security analyst does: validate firewall alerts, trace traffic through NAT
and filter rules, troubleshoot IPsec tunnels, and investigate attacks from
firewall logs.

Two Linux firewalls (nftables + strongSwan IKEv2) connect an HQ office and a
branch office over a simulated internet, all in rootless podman containers on
isolated networks. Nothing leaves your machine.

```
                         simulated internet 203.0.113.0/24
   internet-site .50 ──┬──────────────────────────────┬── attacker .66
                       │                              │
                 wan .10                         wan .20
               ┌──────────┐   IPsec IKEv2 tunnel  ┌───────────┐
               │  fw-hq   │═══════════════════════│ fw-branch │
               └──────────┘   AES-GCM-256, PSK    └───────────┘
            lan .1     dmz .1                         lan .1
               │          │                              │
      hq-pc 10.10.1.10   web-dmz 10.10.3.10       branch-srv 10.10.2.10
      (HQ users)         (public web, published   (branch intranet app)
                          as 203.0.113.10:80)
```

**HQ firewall policy (`fw-hq/nftables.nft`):** default drop on input and
forward, stateful (`ct state established,related`), HQ users may browse the
internet (NAT/masquerade), the public web server is published by port forward
(DNAT), HQ and branch talk only through the IPsec tunnel (with a NAT
exemption), the DMZ cannot reach the LAN, and every drop is logged.

## Quick start

```bash
./lab.sh up            # build image, create networks, start 7 containers
./lab.sh check         # 6 connectivity tests + VPN state: all should PASS
./lab.sh faults        # list the fault tickets
./lab.sh break rule-order      # inject a fault (or: break random)
./lab.sh check         # see what's broken, then investigate and fix it
./lab.sh reveal        # which fault was it (for 'break random')
./lab.sh reset         # restore both firewalls to the known-good config
./lab.sh attack scan   # attacker scans HQ: investigate the firewall log
./lab.sh sh fw-hq      # shell on a firewall (or any container)
./lab.sh down          # remove everything (logs are kept)
```

Logs are written on your machine as they happen:
- `logs/fw-hq/firewall.log`, `logs/fw-branch/firewall.log`: every dropped packet
- `logs/fw-hq/ipsec.log`, `logs/fw-branch/ipsec.log`: IKE negotiation (strongSwan)

## Troubleshooting toolkit (run on a firewall: `./lab.sh sh fw-hq`)

| Question | Command |
|---|---|
| What are the rules, in order, with handles? | `nft -a list ruleset` |
| Which rule is matching? (counters) | `nft list ruleset` after adding `counter` to a rule, or `nft monitor trace` (see below) |
| Follow one packet through every chain | `nft insert rule inet filter forward meta nftrace set 1` then `nft monitor trace` |
| What NAT was applied to a connection? | `conntrack -L` (look for `[UNREPLIED]` and the reply tuple) |
| Is the tunnel up? Is traffic flowing in it? | `swanctl --list-sas` (bytes/packets in and out) |
| What is configured for the tunnel? | `swanctl --list-conns` |
| Kernel IPsec state and policies | `ip xfrm state`, `ip xfrm policy` |
| Is traffic encrypted on the wire? | `tcpdump -ni wan esp or udp port 500 or udp port 4500` |
| Is clear-text traffic leaking out of wan? | `tcpdump -ni wan not esp and not udp port 500` |
| Bring the tunnel up manually and watch | `swanctl --initiate --child lan-lan` |

Edit the working configs on the firewall in `/etc/lab/` and reload them with
`nft -f /etc/lab/nftables.nft` or
`swanctl --load-all --clear --file /etc/lab/swanctl.conf`.
The originals in this folder are never changed; `./lab.sh reset` copies them back.

## Exercises

### Part 1: fault tickets

For each ticket: run `./lab.sh break <fault>` (or `break random` once you've
done them all), read the ticket, then work it like a real incident.
1. Reproduce the symptom with `./lab.sh check`.
2. Collect evidence: logs, rule counters, captures, SA state.
3. Name the root cause in one sentence.
4. Fix it on the firewall itself, not with `reset`, and confirm that `check` passes.
5. Write a short post-incident note: symptom, evidence, cause, fix, and how to prevent it next time.

| Fault | Ticket |
|---|---|
| `rule-order` | HQ users can't open the branch intranet app or plain-HTTP websites since last night's change. Ping still works. |
| `port-forward` | The HQ public website is down from the internet; the web server team says the server is healthy. |
| `no-masquerade` | HQ users can't reach any internet website. The branch VPN works fine. |
| `nat-exemption` | The VPN to the branch shows as up, but HQ users can't reach anything at the branch. |
| `ike-proposal` | The branch VPN dropped after a contractor "hardened" the branch firewall. |
| `psk` | After a scheduled key rotation the branch VPN won't come up. |
| `traffic-selector` | The VPN negotiates but HQ still can't reach the branch servers. |
| `dmz-exposed` | Audit finding: the DMZ web server may be able to reach internal HQ hosts. |

Answers are in `SOLUTIONS.md`. Try each ticket before reading them.

### Part 2: attack investigation

Run `./lab.sh attack scan`, then answer from `logs/fw-hq/firewall.log` only:
1. Which source IP is attacking, when did it start, and how long did it last?
2. How many distinct destination ports and hosts were probed? Which ports?
   (`grep SRC=203.0.113.66 logs/fw-hq/firewall.log | grep -o 'DPT=[0-9]*' | sort | uniq -c | sort -rn`)
3. Which firewall rule (log prefix) dropped the packets, and why are some
   `FW-IN-DROP` and some `FW-FWD-DROP`?
4. The scan reported port 80 open. Was that a real exposure or intended?
   Which rule allowed it?
5. Map it to MITRE ATT&CK (technique ID and tactic).
6. Write the incident ticket: severity, impact, evidence, and recommended
   actions (for example, block the source, rate-limit, alert threshold).

### Part 3: harden it yourself
- Rate-limit new connections to the published web server per source IP (`meter`/`limit`).
- Add a rule that blocks and logs the attacker's IP, and confirm the log shows it.
- Add `counter` to every rule and use the counters to prove which rule handled each test.
- Change the tunnel to stronger IKE settings (for example `aes256gcm16-prfsha384-ecp384`) on both sides.

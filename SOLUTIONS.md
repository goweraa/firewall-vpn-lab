# Solutions

Try each ticket before reading its solution.

## rule-order
- **Symptom:** HQ → branch app and HQ → internet HTTP fail. Ping and HTTPS still work.
- **Evidence:** `logs/fw-hq/firewall.log` shows `FW-POLICY-BLOCK ... DPT=80`.
  `nft -a list chain inet filter forward` shows a new rule, `CHG-1042 block
  clear-text HTTP`, **above** the VPN and browsing accepts. nftables evaluates
  top-down and the first matching verdict wins.
- **Root cause:** a change added a broad `tcp dport 80 drop` before the more
  specific allow rules. It was meant for internet HTTP but also catches
  internal HTTP across the VPN.
- **Fix:** `nft delete rule inet filter forward handle <N>`, or narrow it
  (`oifname "wan" ip daddr != 10.10.2.0/24`) and place it correctly.
- **Prevention:** peer review of change requests, and a post-change connectivity test like `./lab.sh check`.

## port-forward
- **Symptom:** internet → 203.0.113.10:80 times out; the web server itself is fine.
- **Evidence:** the firewall log shows `FW-FWD-DROP IN=wan OUT=dmz ... DST=10.10.3.11 ... DPT=80`:
  the packet was translated (its destination is now an internal address)
  and then dropped. `nft list chain ip nat prerouting` shows
  `dnat to 10.10.3.11:80`, but the forward rule allows only `$WEB` (10.10.3.10).
  The connection never shows in `conntrack -L`, because entries for packets
  dropped in the forward chain are never confirmed. `nft monitor trace`
  shows the whole path.
- **Root cause:** the DNAT target is the wrong internal IP (typo).
- **Fix:** change the DNAT target back to `$WEB:80` and reload.

## no-masquerade
- **Symptom:** HQ users can't reach internet sites. The VPN and port forward still work.
- **Evidence:** `tcpdump -ni wan tcp port 80` on fw-hq shows SYNs leaving with
  **source 10.10.1.10**, a private address, and no replies. The internet host
  has no route back to RFC 1918 space. The `masquerade` rule is missing from
  `nat postrouting`.
- **Root cause:** outbound source NAT was removed.
- **Fix:** restore `oifname "wan" ip saddr { $HQ_LAN, $DMZ } masquerade`.

## nat-exemption
- **Symptom:** HQ → branch fails although `swanctl --list-sas` may show the
  IKE SA as ESTABLISHED. Internet access works.
- **Evidence:** on fw-hq, `tcpdump -ni wan host 10.10.2.10` shows traffic to
  the branch leaving in **clear text with source 203.0.113.10**, not as ESP.
  The packets were masqueraded, so they no longer match the IPsec policy
  `10.10.1.0/24 === 10.10.2.0/24`. The CHILD_SA byte counters stay at 0.
- **Root cause:** the NAT exemption rule (`ip daddr $BRANCH accept` in
  postrouting, before masquerade) was removed.
- **Fix:** put the exemption back **above** the masquerade rule.
- **Real-world note:** "tunnel up, no traffic" is one of the most common VPN tickets. Always check the NAT exemption.

## ike-proposal
- **Symptom:** nothing crosses the VPN. No SAs come up.
- **Evidence:** `logs/fw-*/ipsec.log` shows `received proposals: IKE:AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024`
  next to `configured proposals: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048`,
  `no acceptable ENCRYPTION_ALGORITHM found`, and on the other side
  `received NO_PROPOSAL_CHOSEN notify error`. This is a phase 1 (IKE_SA) failure.
- **Root cause:** the branch IKE proposal was changed to
  `aes128-sha1-modp1024`, which HQ doesn't accept. It's also weaker:
  SHA-1 and a 1024-bit DH group are deprecated, so "hardened" is wrong.
- **Fix:** make both sides use the same proposal, ideally strong, e.g. `aes256-sha256-modp2048` or better.

## psk
- **Symptom:** the VPN won't come up.
- **Evidence:** ipsec.log shows `tried 1 shared key for 'branch.lab' - 'hq.lab', but MAC mismatched`
  on one side and `received AUTHENTICATION_FAILED notify error` on the other. The proposals were accepted, so phase 1
  crypto negotiation worked, but authentication failed.
- **Root cause:** the pre-shared keys differ on the two sides after the rotation.
- **Fix:** set the same `secret` on both, then `swanctl --load-all --clear`.
  Rotate keys through a coordinated change, never one side at a time.

## traffic-selector
- **Symptom:** IKE comes up, but the CHILD_SA (phase 2) fails, so no traffic.
- **Evidence:** ipsec.log shows `traffic selectors ... 10.10.2.0/24 === ... 10.10.1.0/24 unacceptable`
  and `TS_UNACCEPTABLE`. `swanctl --list-sas` shows the IKE SA but no `lan-lan` CHILD_SA.
- **Root cause:** the branch's `remote_ts` was changed to `10.10.11.0/24`
  (typo), so the networks the two sides want to protect don't match.
- **Fix:** both sides must mirror each other: HQ local = branch remote, and the reverse.
- **Phase 1 vs phase 2:** NO_PROPOSAL_CHOSEN on IKE_SA_INIT and
  AUTHENTICATION_FAILED are phase 1 problems. TS_UNACCEPTABLE, or a
  NO_PROPOSAL_CHOSEN on CREATE_CHILD_SA, is a phase 2 problem.

## dmz-exposed
- **Symptom:** `check` shows the DMZ web server can reach the HQ PC.
- **Evidence:** `nft -a list chain inet filter forward` contains
  `iifname "dmz" accept comment "TEMP vendor troubleshooting - remove after ticket 5531"`.
  No `FW-FWD-DROP` entries appear for DMZ → LAN traffic.
- **Root cause:** a temporary any-any rule was never removed. If the
  internet-facing web server is compromised, the attacker can move laterally
  into the LAN (MITRE ATT&CK TA0008 Lateral Movement).
- **Fix:** delete the rule. Temporary rules need an owner, an expiry date and a review.

## Attack investigation (Part 2)
- **Source:** 203.0.113.66, a burst of SYNs within a few seconds (nmap `-sS`, window 1024, no ACK).
- **Targets:** the firewall's WAN IP on its top 100 ports, then hosts 10.10.1.0–15
  on 22/80/443/445/3389.
  - Packets **to the firewall itself** hit the input chain, so they're logged as `FW-IN-DROP`.
  - Packets **routed through** toward the LAN hit the forward chain, so they're logged as `FW-FWD-DROP`.
- **Port 80 open:** this is intended. It's the published web server (DNAT + forward rule `port forward to public web`).
- **MITRE:** T1046 Network Service Discovery (tactic: Discovery). The LAN sweep is also Remote System Discovery, T1018.
- **Recommended actions:** block or deny-list the source, alert on more than N
  distinct ports from one source per minute, rate-limit new connections, and
  confirm that no internal host answered.

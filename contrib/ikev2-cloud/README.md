# OpenVPN IKEv2 Cloud Hardening Profile

This directory contains optional deployment artifacts for the experimental
OpenVPN-owned IKEv2 helper architecture. They are not core OpenVPN policy and
do not replace OpenVPN authorization, provider-session state, or XFRM lease
checks.

The intended public-cloud shape is:

1. Cloud security group or NACL permits only required administrator access and
   UDP 500/4500 from the intended client population.
2. Host nftables policy loads before OpenVPN opens IKEv2 listeners.
3. OpenVPN owns provider admission, route policy, XFRM leases, marks, reqids,
   and cleanup predicates.
4. VPN clients land in a constrained VPN DMZ.
5. VPN clients can reach only a reverse proxy/application gateway VIP and
   programmed ports by default.
6. Backend services deny direct VPN-client layer-3 reachability and accept only
   the application gateway identity or network.

Files:

- `openvpn-ikev2-cloud.nft`: nftables template for a deny-by-default cloud VM
  host profile.
- `openvpn-ikev2-systemd-hardening.conf`: example systemd drop-in settings for
  an OpenVPN server instance that supervises an IKEv2 helper.
- `validate-openvpn-ikev2-cloud.sh`: local sanity checker for the expected
  nftables table, metadata blocks, Docker/socket exposure blocks, IPv6 leak
  blocks, and listener state.

These files use documentation ranges and placeholder interface names. Review
and replace all definitions before use on a real host.

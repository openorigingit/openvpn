#!/bin/sh
#
# Validate the expected public-cloud hardening shape for the experimental
# OpenVPN IKEv2 helper deployment. This script is read-only.

set -eu

NFT_TABLE="${NFT_TABLE:-inet openvpn_ikev2}"
VPN_IF="${VPN_IF:-xfrm0}"
IKE_PORTS="${IKE_PORTS:-500 4500}"

failures=0

check()
{
    desc="$1"
    shift
    if "$@"; then
        printf 'ok: %s\n' "$desc"
    else
        printf 'FAIL: %s\n' "$desc" >&2
        failures=$((failures + 1))
    fi
}

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

nft_table()
{
    nft list table $NFT_TABLE 2>/dev/null
}

table_has()
{
    pattern="$1"
    nft_table | grep -F "$pattern" >/dev/null
}

listeners_have_ike_ports()
{
    have_cmd ss || return 1
    for port in $IKE_PORTS; do
        ss -H -lun | awk '{ print $5 }' | grep -E "[:.]$port$" >/dev/null || return 1
    done
}

check 'nft command is installed' have_cmd nft
check 'nftables IKEv2 table exists' nft_table
check 'metadata IPv4 endpoint is blocked' table_has '169.254.169.254'
check 'AWS IPv6 metadata endpoint is blocked' table_has 'fd00:ec2::254'
check 'VPN interface has explicit deny path' table_has "iifname \"$VPN_IF\" counter drop"
check 'raw ESP is denied' table_has 'ip protocol esp drop'
check 'IKE UDP listeners are present' listeners_have_ike_ports

if have_cmd docker; then
    if docker context inspect >/dev/null 2>&1; then
        if [ -S /var/run/docker.sock ]; then
            mode="$(stat -c '%a' /var/run/docker.sock 2>/dev/null || printf unknown)"
            case "$mode" in
                *6|*7)
                    printf 'FAIL: Docker socket appears writable by broad users: %s\n' "$mode" >&2
                    failures=$((failures + 1))
                    ;;
                *)
                    printf 'ok: Docker socket is not broadly writable: %s\n' "$mode"
                    ;;
            esac
        fi
    fi
fi

if [ "$failures" -ne 0 ]; then
    printf '%s validation check(s) failed\n' "$failures" >&2
    exit 1
fi

printf 'ok: cloud hardening validation completed\n'

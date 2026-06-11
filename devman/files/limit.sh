#!/bin/sh
# nftables-based rate limiting (no kernel module dependency)
CID=$2
IP=$3
RATE=${4:-0}

case "$1" in
  init)
    nft add table ip devman 2>/dev/null
    nft add chain ip devman limit_in { type filter hook forward priority filter - 1; } 2>/dev/null
    nft add chain ip devman limit_out { type filter hook forward priority filter - 1; } 2>/dev/null
    ;;
  set)
    # Remove old rules for this IP
    nft delete rule ip devman limit_in handle $(nft -a list chain ip devman limit_in 2>/dev/null | grep "$IP " | grep -o "handle [0-9]*" | cut -d' ' -f2) 2>/dev/null
    # Add new limit: rate in kbps → translate to byte rate
    # nft limit syntax: limit rate X bytes/second
    # Kbps to bytes/s: * 1000 / 8 = * 125
    LIMIT=$((RATE * 125))
    nft add rule ip devman limit_in ip saddr $IP limit rate $LIMIT bytes/second drop 2>/dev/null
    ;;
  del)
    nft delete rule ip devman limit_in handle $(nft -a list chain ip devman limit_in 2>/dev/null | grep "$IP " | grep -o "handle [0-9]*" | cut -d' ' -f2) 2>/dev/null
    ;;
  clean)
    nft flush chain ip devman limit_in 2>/dev/null
    ;;
esac

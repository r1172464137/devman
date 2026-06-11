#!/bin/sh
# dnsmasq dhcp-script hook for devman
[ "$1" = "add" ] || [ "$1" = "old" ] || exit 0
curl -s -X POST http://127.0.0.1:9999/api/dhcp-event \
  -H "Content-Type: application/json" \
  -d "{\"mac\":\"$2\",\"ip\":\"$3\",\"hostname\":\"${DNSMASQ_SUPPLIED_HOSTNAME:-}\",\"vendor_class\":\"${DNSMASQ_VENDOR_CLASS:-}\",\"opt55\":\"${DNSMASQ_REQUESTED_OPTIONS:-}\"}" &

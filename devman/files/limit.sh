#!/bin/sh
# tc htb rate limiting for devman
CID=$2; IP=$3; RATE=${4:-0}; IF=br-lan
case "$1" in
  init) tc qdisc add dev $IF root handle 1: htb default 30 ;;
  set)
    tc filter del dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID
    tc class del dev $IF parent 1: classid 1:$CID
    tc class add dev $IF parent 1: classid 1:$CID htb rate ${RATE}kbit ceil ${RATE}kbit
    tc filter add dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID
    ;;
  del)
    tc filter del dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID
    tc class del dev $IF parent 1: classid 1:$CID
    ;;
  setdn)
    DNID="1${CID}"
    tc filter del dev $IF parent 1: prio 1 u32 match ip dst $IP flowid 1:$DNID
    tc class del dev $IF parent 1: classid 1:$DNID
    tc class add dev $IF parent 1: classid 1:$DNID htb rate ${RATE}kbit ceil ${RATE}kbit
    tc filter add dev $IF parent 1: prio 1 u32 match ip dst $IP flowid 1:$DNID
    ;;
  deldn)
    DNID="1${CID}"
    tc filter del dev $IF parent 1: prio 1 u32 match ip dst $IP flowid 1:$DNID
    tc class del dev $IF parent 1: classid 1:$DNID
    ;;
  clean) tc qdisc del dev $IF root ;;
esac

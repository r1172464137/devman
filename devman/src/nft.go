package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func nftInit() {
	exec.Command("nft", "add", "table", "ip", "devman").Run()
	exec.Command("nft", "add", "set", "ip", "devman", "blocked_ip", "{", "type", "ipv4_addr", ";", "}").Run()
	exec.Command("nft", "add", "chain", "ip", "devman", "forward", "{", "type", "filter", "hook", "forward", "priority", "filter", "-", "1", ";", "}").Run()
	exec.Command("nft", "add", "rule", "ip", "devman", "forward", "ip", "saddr", "@blocked_ip", "drop").Run()
	exec.Command("nft", "add", "set", "ip", "devman", "ul_mark", "{", "type", "ipv4_addr", ";", "}").Run()
	exec.Command("nft", "add", "set", "ip", "devman", "dl_mark", "{", "type", "ipv4_addr", ";", "}").Run()
	exec.Command("nft", "add", "rule", "ip", "devman", "forward", "ip", "saddr", "@ul_mark", "meta", "mark", "set", "0x80000000").Run()
	exec.Command("nft", "add", "rule", "ip", "devman", "forward", "ip", "daddr", "@dl_mark", "meta", "mark", "set", "0x40000000").Run()
	exec.Command("nft", "add", "chain", "ip", "devman", "post", "{", "type", "filter", "hook", "postrouting", "priority", "filter", "-", "2", ";", "}").Run()
	exec.Command("nft", "add", "rule", "ip", "devman", "post", "ip", "saddr", "@ul_mark", "meta", "mark", "set", "0x80000000").Run()
	exec.Command("nft", "add", "rule", "ip", "devman", "post", "ip", "daddr", "@dl_mark", "meta", "mark", "set", "0x40000000").Run()
}

func nftBlock(ip string)   { exec.Command("nft", "add", "element", "ip", "devman", "blocked_ip", "{", ip, "}").Run() }
func nftUnblock(ip string) { exec.Command("nft", "delete", "element", "ip", "devman", "blocked_ip", "{", ip, "}").Run() }

func restoreRateLimits() {
	rows, _ := db.Query("SELECT DISTINCT ipv4, COALESCE(rate_limit,0), COALESCE(rate_limit_dn,0) FROM devices WHERE ipv4!='' AND (rate_limit>0 OR rate_limit_dn>0)")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var ip string
			var ul, dl int
			rows.Scan(&ip, &ul, &dl)
			nftSetLimit(ip, ul, dl)
		}
	}
}

func nftCleanup() {
	exec.Command("nft", "delete", "table", "ip", "devman").Run()
}

func nftSetLimit(ip string, ulBps, dlBps int) {
	limitMu.Lock()
	defer limitMu.Unlock()
	tcLazyInit()

	exec.Command("nft", "delete", "element", "ip", "devman", "ul_mark", "{", ip, "}").Run()
	if ulBps > 0 {
		exec.Command("nft", "add", "element", "ip", "devman", "ul_mark", "{", ip, "}").Run()
	}
	prio := int(hashIp(ip))
	ulKbps := ulBps / 1000
	if ulKbps < 1 {
		ulKbps = 1
	}
	if ulBps > 0 {
		exec.Command("tc", "class", "add", "dev", "ifb0", "parent", "1:1", "classid", fmt.Sprintf("1:%d", prio),
			"htb", "rate", fmt.Sprintf("%d", ulKbps)+"kbit", "ceil", fmt.Sprintf("%d", ulKbps)+"kbit", "burst", "15k", "cburst", "15k").Run()
		exec.Command("tc", "class", "change", "dev", "ifb0", "parent", "1:1", "classid", fmt.Sprintf("1:%d", prio),
			"htb", "rate", fmt.Sprintf("%d", ulKbps)+"kbit", "ceil", fmt.Sprintf("%d", ulKbps)+"kbit", "burst", "15k", "cburst", "15k").Run()
		exec.Command("tc", "filter", "add", "dev", "ifb0", "parent", "1:0", "prio", fmt.Sprintf("%d", prio),
			"protocol", "ip", "u32", "match", "ip", "src", ip, "flowid", fmt.Sprintf("1:%d", prio)).Run()
		exec.Command("tc", "filter", "replace", "dev", "ifb0", "parent", "1:0", "prio", fmt.Sprintf("%d", prio),
			"protocol", "ip", "u32", "match", "ip", "src", ip, "flowid", fmt.Sprintf("1:%d", prio)).Run()
	} else {
		exec.Command("tc", "filter", "del", "dev", "ifb0", "parent", "1:0", "prio", fmt.Sprintf("%d", prio),
			"protocol", "ip", "u32", "match", "ip", "src", ip).Run()
		exec.Command("tc", "class", "del", "dev", "ifb0", "parent", "1:1", "classid", fmt.Sprintf("1:%d", prio)).Run()
	}

	exec.Command("nft", "delete", "element", "ip", "devman", "dl_mark", "{", ip, "}").Run()
	if dlBps > 0 {
		exec.Command("nft", "add", "element", "ip", "devman", "dl_mark", "{", ip, "}").Run()
	}
	dlKbps := dlBps / 1000
	if dlKbps < 1 {
		dlKbps = 1
	}
	if dlBps > 0 {
		exec.Command("tc", "class", "add", "dev", lanIface, "parent", "1:1", "classid", fmt.Sprintf("1:%d", prio),
			"htb", "rate", fmt.Sprintf("%d", dlKbps)+"kbit", "ceil", fmt.Sprintf("%d", dlKbps)+"kbit", "burst", "15k", "cburst", "15k").Run()
		exec.Command("tc", "class", "change", "dev", lanIface, "parent", "1:1", "classid", fmt.Sprintf("1:%d", prio),
			"htb", "rate", fmt.Sprintf("%d", dlKbps)+"kbit", "ceil", fmt.Sprintf("%d", dlKbps)+"kbit", "burst", "15k", "cburst", "15k").Run()
		exec.Command("tc", "filter", "add", "dev", lanIface, "parent", "1:0", "prio", fmt.Sprintf("%d", prio),
			"protocol", "ip", "u32", "match", "ip", "dst", ip, "flowid", fmt.Sprintf("1:%d", prio)).Run()
		exec.Command("tc", "filter", "replace", "dev", lanIface, "parent", "1:0", "prio", fmt.Sprintf("%d", prio),
			"protocol", "ip", "u32", "match", "ip", "dst", ip, "flowid", fmt.Sprintf("1:%d", prio)).Run()
	} else {
		exec.Command("tc", "filter", "del", "dev", lanIface, "parent", "1:0", "prio", fmt.Sprintf("%d", prio),
			"protocol", "ip", "u32", "match", "ip", "dst", ip).Run()
		exec.Command("tc", "class", "del", "dev", lanIface, "parent", "1:1", "classid", fmt.Sprintf("1:%d", prio)).Run()
	}
}

func hashIp(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 1
	}
	a, _ := atoi(parts[2])
	b, _ := atoi(parts[3])
	return uint32(a)*256 + uint32(b)
}

func atoi(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

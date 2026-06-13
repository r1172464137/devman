package main

import (
	"os/exec"
	"strings"
	"time"
)

// ====== speed calculation via conntrack ======

var (
	spPrevUp   = map[string]uint64{}
	spPrevDown = map[string]uint64{}
	spFirst    = map[string]bool{}
	spLastTime time.Time
)

func calcSpeed() {
	now := time.Now().Unix()
	out, _ := exec.Command("/usr/sbin/conntrack", "-L").Output()
	curUp := map[string]uint64{}
	curDown := map[string]uint64{}
	for _, line := range strings.Split(string(out), "\n") {
		sIdx := strings.Index(line, " src=")
		if sIdx < 0 {
			continue
		}
		src := strings.SplitN(line[sIdx+5:], " ", 2)[0]
		if !isLAN(src) || src == "127.0.0.1" {
			continue
		}
		fb := strings.Index(line, "bytes=")
		lb := strings.LastIndex(line, "bytes=")
		if fb < 0 {
			continue
		}
		up, _ := atoui(strings.SplitN(line[fb+6:], " ", 2)[0])
		curUp[src] += up
		if lb > fb {
			dn, _ := atoui(strings.SplitN(line[lb+6:], " ", 2)[0])
			curDown[src] += dn
		}
	}
	if spLastTime.IsZero() {
		for ip := range curUp {
			spPrevUp[ip] = curUp[ip]
		}
		for ip := range curDown {
			spPrevDown[ip] = curDown[ip]
		}
		spLastTime = time.Now()
		return
	}
	interval := float64(time.Since(spLastTime).Seconds())
	if interval < 1 {
		interval = 3
	}
	spLastTime = time.Now()
	mu.Lock()
	allIPs := map[string]bool{}
	for ip := range curUp {
		allIPs[ip] = true
	}
	for ip := range curDown {
		allIPs[ip] = true
	}
	for ip := range allIPs {
		if !spFirst[ip] {
			spFirst[ip] = true
			spPrevUp[ip] = curUp[ip]
			spPrevDown[ip] = curDown[ip]
			continue
		}
		var up, dn uint64
		if curUp[ip] > spPrevUp[ip] {
			up = uint64(float64(curUp[ip]-spPrevUp[ip]) / interval * 8)
		}
		if curDown[ip] > spPrevDown[ip] {
			dn = uint64(float64(curDown[ip]-spPrevDown[ip]) / interval * 8)
		}
		spPrevUp[ip] = curUp[ip]
		spPrevDown[ip] = curDown[ip]
		if up > 0 || dn > 0 {
			db.Exec("INSERT INTO traffic (device_id,speed_in,speed_out,recorded_at) SELECT id,?,?,? FROM devices WHERE ipv4=? AND ipv4!=''", up, dn, now, ip)
		}
	}
	mu.Unlock()
}

func atoui(s string) (uint64, error) {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

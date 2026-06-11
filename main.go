package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

type DeviceProfile struct {
	ID         int64  `json:"id"`
	Alias      string `json:"alias"`
	Hostname   string `json:"hostname"`
	DeviceType string `json:"device_type"`
	CurrentIP  string `json:"current_ip"`
	CurrentMAC string `json:"current_mac"`
	IsBlocked  bool   `json:"is_blocked"`
	RateLimit  int    `json:"rate_limit"`
	LastSeen   int64  `json:"last_seen"`
	Online     string `json:"online"`
	SpeedOut   uint64 `json:"speed_out"`
	NumMACs    int    `json:"num_macs"`
}

var (
	db        *sql.DB
	mu        sync.RWMutex
	prevBytes = map[string]uint64{}
	firstSeen = map[string]bool{}
	speedMu   sync.Mutex
	scriptDir = "/usr/lib/devman"
)

func main() {
	log.SetFlags(log.LstdFlags)
	os.MkdirAll("/etc/devman", 0755)
	os.MkdirAll(scriptDir, 0755)

	var err error
	db, err = sql.Open("sqlite", "/etc/devman/devman.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	initDB()

	installScripts()
	initTC()
	initNFT()

	go neightLoop()
	go conntrackLoop()
	go leaseLoop()
	go speedLoop()
	go reconcileLoop()

	http.HandleFunc("/api/devices", apiDevices)
	http.HandleFunc("/api/block", apiBlock)
	http.HandleFunc("/api/limit", apiLimit)
	http.HandleFunc("/api/dhcp-event", apiDHCPEvent)
	go http.ListenAndServe(":9999", nil)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	// cleanup
	exec.Command(scriptDir+"/block.sh", "init").Run()
	exec.Command(scriptDir+"/limit.sh", "clean").Run()
}

// ======== init ========

func initDB() {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mac TEXT DEFAULT '', hostname TEXT DEFAULT '',
			vendor_class TEXT DEFAULT '', opt55_hash TEXT DEFAULT '',
			device_type TEXT DEFAULT 'Unknown',
			alias TEXT DEFAULT '', ipv4 TEXT DEFAULT '',
			is_blocked INTEGER DEFAULT 0, rate_limit INTEGER DEFAULT 0,
			last_seen INTEGER DEFAULT 0, first_seen INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS device_macs (
			device_id INTEGER NOT NULL, mac TEXT NOT NULL,
			first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS traffic (
			device_id INTEGER NOT NULL, speed_out INTEGER DEFAULT 0,
			recorded_at INTEGER DEFAULT 0
		)`,
	} {
		db.Exec(q)
	}
}

func installScripts() {
	scripts := map[string]string{
		"block.sh": `#!/bin/sh
# nftables set-based blocking
case "$1" in
  init)
    nft add table ip devman 2>/dev/null
    nft add set ip devman blocked_ip { type ipv4_addr\; } 2>/dev/null
    nft add chain ip devman forward { type filter hook forward priority filter - 1\; } 2>/dev/null
    nft add rule ip devman forward ip saddr @blocked_ip drop 2>/dev/null
    ;;
  add) nft add element ip devman blocked_ip { $2 } 2>/dev/null ;;
  del) nft delete element ip devman blocked_ip { $2 } 2>/dev/null ;;
esac`,
		"limit.sh": `#!/bin/sh
# tc htb rate limiting, uses device_id as classid
CID=$2; IP=$3; RATE=${4:-0}; IF=br-lan
case "$1" in
  init) tc qdisc add dev $IF root handle 1: htb default 30 2>/dev/null ;;
  set)
    tc filter del dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    tc class del dev $IF parent 1: classid 1:$CID 2>/dev/null
    tc class add dev $IF parent 1: classid 1:$CID htb rate ${RATE}kbit ceil ${RATE}kbit 2>/dev/null
    tc filter add dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    ;;
  del)
    tc filter del dev $IF parent 1: prio 1 u32 match ip src $IP flowid 1:$CID 2>/dev/null
    tc class del dev $IF parent 1: classid 1:$CID 2>/dev/null
    ;;
  clean)
    tc qdisc del dev $IF root 2>/dev/null
    tc qdisc add dev $IF root handle 1: htb default 30 2>/dev/null
    ;;
esac`,
		"dhcp-hook.sh": `#!/bin/sh
[ "$1" = "add" ] || [ "$1" = "old" ] || exit 0
curl -s -X POST http://127.0.0.1:9999/api/dhcp-event -H "Content-Type: application/json" \
  -d "{\"mac\":\"$2\",\"ip\":\"$3\",\"hostname\":\"${DNSMASQ_SUPPLIED_HOSTNAME:-}\",\"vendor_class\":\"${DNSMASQ_VENDOR_CLASS:-}\",\"opt55\":\"${DNSMASQ_REQUESTED_OPTIONS:-}\"}" &`,
	}
	for name, content := range scripts {
		os.WriteFile(scriptDir+"/"+name, []byte(content), 0755)
	}
	// Ensure dnsmasq hook
	hook := scriptDir + "/dhcp-hook.sh"
	cfg, _ := os.ReadFile("/etc/dnsmasq.conf")
	if !strings.Contains(string(cfg), "dhcp-script="+hook) {
		f, _ := os.OpenFile("/etc/dnsmasq.conf", os.O_APPEND|os.O_WRONLY, 0644)
		if f != nil {
			f.WriteString("\ndhcp-script=" + hook + "\ndhcp-authoritative\n")
			f.Close()
		}
	}
}

func initTC()  { exec.Command(scriptDir+"/limit.sh", "init").Run() }
func initNFT() { exec.Command(scriptDir+"/block.sh", "init").Run() }

// ======== discovery ========

func neightLoop() {
	for {
		out, _ := exec.Command("sh", "-c", "ip neigh show | grep REACHABLE").Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 {
				upsertDevice(f[0], f[4], "", "", "")
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func conntrackLoop() {
	for {
		cmd := exec.Command("conntrack", "-E")
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()
		buf := make([]byte, 8192)
		var ip, dst string
		for {
			n, err := stdout.Read(buf)
			if n == 0 && err != nil {
				break
			}
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				if strings.Contains(line, "src=") {
					ip = field(line, "src=")
				}
				if strings.Contains(line, "dst=") && strings.Contains(line, "bytes=") {
					dst = field(line, "dst=")
					if ip != "" && dst != "" && isLAN(ip) && !isLAN(dst) {
						upsertDevice(ip, "", "", "", "")
					}
					ip, dst = "", ""
				}
			}
		}
		cmd.Process.Kill()
		time.Sleep(time.Second)
	}
}

func leaseLoop() {
	for {
		out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan 2>/dev/null | grep -v '^#'").Output()
		mu.Lock()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && isLAN(f[0]) && f[1] != "" {
				db.Exec("UPDATE devices SET hostname=CASE WHEN hostname='' THEN ? ELSE hostname END WHERE ipv4=? OR mac IN (SELECT mac FROM device_macs)", f[1], f[0])
			}
		}
		mu.Unlock()
		time.Sleep(10 * time.Second)
	}
}

// ======== matching ========

func upsertDevice(ip, mac, hostname, vendorClass, opt55 string) int64 {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now().Unix()

	if mac == "" && !strings.Contains(ip, ":") {
		mac = getMAC(ip)
	}
	fpHash := hashOpt55(opt55)
	if hostname == "" {
		hostname = getHostname(ip)
	}
	devType := detectType(hostname, vendorClass)

	// Tier 1: MAC
	if mac != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE mac=?", mac).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
		if db.QueryRow("SELECT device_id FROM device_macs WHERE mac=? LIMIT 1", mac).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
	}

	// Tier 2: Hostname
	if hostname != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE hostname=? LIMIT 1", hostname).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
	}

	// Tier 3: DHCP fingerprint
	if vendorClass != "" && opt55 != "" {
		var id int64
		if db.QueryRow("SELECT id FROM devices WHERE vendor_class=? AND opt55_hash=?", vendorClass, fpHash).Scan(&id) == nil {
			updateDev(id, ip, mac, hostname, vendorClass, fpHash, now)
			return id
		}
	}

	// New device
	ipv4 := ""
	if !strings.Contains(ip, ":") {
		ipv4 = ip
	}
	r, _ := db.Exec("INSERT INTO devices (mac,hostname,vendor_class,opt55_hash,device_type,ipv4,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
		mac, hostname, vendorClass, fpHash, devType, ipv4, now, now)
	id, _ := r.LastInsertId()
	if mac != "" {
		db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac,first_seen,last_seen) VALUES (?,?,?,?)", id, mac, now, now)
	}
	return id
}

func updateDev(id int64, ip, mac, hostname, vendorClass, fpHash string, now int64) {
	q := "UPDATE devices SET last_seen=?"
	args := []interface{}{now}
	if mac != "" {
		q += ", mac=?"
		args = append(args, mac)
	}
	if hostname != "" {
		q += ", hostname=CASE WHEN hostname='' THEN ? ELSE hostname END"
		args = append(args, hostname)
	}
	if vendorClass != "" {
		q += ", vendor_class=?"
		args = append(args, vendorClass)
	}
	if fpHash != "" {
		q += ", opt55_hash=?"
		args = append(args, fpHash)
	}
	if ip != "" && !strings.Contains(ip, ":") {
		q += ", ipv4=CASE WHEN ipv4='' THEN ? ELSE ipv4 END"
		args = append(args, ip)
	}
	q += " WHERE id=?"
	args = append(args, id)
	db.Exec(q, args...)
	if mac != "" {
		db.Exec("INSERT OR IGNORE INTO device_macs (device_id,mac,first_seen,last_seen) VALUES (?,?,?,?)", id, mac, now, now)
	}
}

func detectType(hostname, vendorClass string) string {
	h := strings.ToLower(hostname)
	v := strings.ToLower(vendorClass)
	for _, kw := range []string{"iphone", "ipad", "apple", "macbook"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "Apple"
		}
	}
	for _, kw := range []string{"android", "pixel", "samsung"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "Android"
		}
	}
	if strings.Contains(h, "desktop-") || strings.Contains(h, "windows") {
		return "Windows"
	}
	if strings.Contains(h, "ubuntu") || strings.Contains(h, "raspberry") || strings.Contains(h, "openwrt") || strings.Contains(v, "dhcpcd-") {
		return "Linux"
	}
	for _, kw := range []string{"xiaomi", "lumi", "esp", "sonoff", "tasmota"} {
		if strings.Contains(h, kw) || strings.Contains(v, kw) {
			return "IoT"
		}
	}
	return "Unknown"
}

// ======== speed ========

func speedLoop() {
	for {
		time.Sleep(3 * time.Second)
		now := time.Now().Unix()
		out, _ := exec.Command("conntrack", "-L").Output()
		cur := map[string]uint64{}
		var ip string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "src=") {
				ip = field(line, "src=")
			}
			if strings.Contains(line, "bytes=") && ip != "" {
				bs := field(line, "bytes=")
				n, _ := atoui(bs)
				if isLAN(ip) && ip != "127.0.0.1" {
					cur[ip] += n
				}
			}
		}
		speedMu.Lock()
		mu.Lock()
		for ip, total := range cur {
			prev, ok := prevBytes[ip]
			prevBytes[ip] = total
			if !firstSeen[ip] {
				firstSeen[ip] = true
				continue
			}
			if !ok {
				continue
			}
			delta := total - prev
			speed := uint64(float64(delta) / 3.0 * 8)
			if speed > 0 {
				db.Exec("INSERT INTO traffic (device_id,speed_out,recorded_at) SELECT id,?,? FROM devices WHERE ipv4=? AND ipv4!=''", speed, now, ip)
			}
		}
		mu.Unlock()
		speedMu.Unlock()

		// Online status
		mu.Lock()
		db.Exec(`UPDATE devices SET last_seen=? WHERE ipv4 IN (SELECT ipv4 FROM devices WHERE last_seen>?)`, now, now-5)
		mu.Unlock()
	}
}

// ======== rules reconcile ========

func reconcileLoop() {
	for {
		time.Sleep(5 * time.Second)
		mu.Lock()
		rows, _ := db.Query("SELECT id, ipv4, is_blocked, rate_limit FROM devices WHERE ipv4!=''")
		if rows != nil {
			for rows.Next() {
				var id int64
				var ip string
				var b, r int
				rows.Scan(&id, &ip, &b, &r)
				if b == 1 {
					exec.Command(scriptDir+"/block.sh", "add", ip).Run()
				} else {
					exec.Command(scriptDir+"/block.sh", "del", ip).Run()
				}
				if r > 0 {
					exec.Command(scriptDir+"/limit.sh", "set", fmt.Sprintf("%d", id), ip, fmt.Sprintf("%d", r)).Run()
				} else {
					exec.Command(scriptDir+"/limit.sh", "del", fmt.Sprintf("%d", id), ip, "0").Run()
				}
			}
			rows.Close()
		}
		mu.Unlock()
	}
}

// ======== API ========

func apiDevices(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	rows, _ := db.Query(`SELECT d.id, d.alias, d.hostname, d.device_type, d.ipv4, d.mac, d.is_blocked, d.rate_limit, d.last_seen,
		CASE WHEN d.last_seen > ? THEN 'green' WHEN d.last_seen > ? THEN 'yellow' ELSE 'gray' END,
		(SELECT COUNT(*) FROM device_macs WHERE device_id=d.id)
		FROM devices d ORDER BY d.last_seen DESC`, time.Now().Unix()-120, time.Now().Unix()-1800)
	w.Header().Set("Content-Type", "application/json")
	if rows == nil {
		w.Write([]byte("[]"))
		return
	}
	defer rows.Close()
	var devs []DeviceProfile
	for rows.Next() {
		var d DeviceProfile
		var b int
		rows.Scan(&d.ID, &d.Alias, &d.Hostname, &d.DeviceType, &d.CurrentIP, &d.CurrentMAC, &b, &d.RateLimit, &d.LastSeen, &d.Online, &d.NumMACs)
		d.IsBlocked = b == 1
		db.QueryRow("SELECT COALESCE(speed_out,0) FROM traffic WHERE device_id=? ORDER BY recorded_at DESC LIMIT 1", d.ID).Scan(&d.SpeedOut)
		devs = append(devs, d)
	}
	json.NewEncoder(w).Encode(devs)
}

func apiDHCPEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC, IP, Hostname, VendorClass, Opt55 string
	}
	json.NewDecoder(r.Body).Decode(&req)
	upsertDevice(req.IP, req.MAC, req.Hostname, req.VendorClass, req.Opt55)
	w.Write([]byte(`{"ok":true}`))
}

func apiBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID int64 `json:"device_id"`
		Block    bool  `json:"block"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	v := 0
	if req.Block {
		v = 1
	}
	db.Exec("UPDATE devices SET is_blocked=? WHERE id=?", v, req.DeviceID)
	w.Write([]byte(`{"ok":true}`))
}

func apiLimit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID  int64  `json:"device_id"`
		RateLimit int    `json:"rate_limit"`
		Alias     string `json:"alias"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Alias != "" {
		db.Exec("UPDATE devices SET alias=? WHERE id=?", req.Alias, req.DeviceID)
	}
	if req.RateLimit >= 0 {
		db.Exec("UPDATE devices SET rate_limit=? WHERE id=?", req.RateLimit, req.DeviceID)
	}
	w.Write([]byte(`{"ok":true}`))
}

// ======== helpers ========

func getMAC(ip string) string {
	out, _ := exec.Command("sh", "-c", "ip neigh show | grep '"+ip+"'").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, "lladdr "); idx > 0 {
			return strings.SplitN(line[idx+7:], " ", 2)[0]
		}
	}
	return ""
}

func getHostname(ip string) string {
	out, _ := exec.Command("sh", "-c", "cat /tmp/hosts/dhcp.* /tmp/hosts/odhcpd.hosts.lan 2>/dev/null | grep '^"+ip+"[\t ]' | head -1").Output()
	f := strings.Fields(string(out))
	if len(f) >= 2 {
		return f[1]
	}
	return ""
}

func hashOpt55(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

func field(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	return strings.SplitN(line[idx+len(key):], " ", 2)[0]
}

func isLAN(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			ip.IsPrivate()
	}
	return len(ip) == net.IPv6len &&
		((ip[0]&0xfe) == 0xfc ||
			(ip[0] == 0xfe && ip[1]&0xc0 == 0x80))
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

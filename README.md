# 🛡️ XDP-Firewall v2.0

> **eBPF/XDP Firewall**: Ultra-low latency kernel-level packet filtering with stateful connection tracking, advanced rate limiting, and an intuitive web management console.

Welcome to the **XDP-Firewall** repository. This project provides bare-metal network protection by leveraging the raw power of **eBPF** (Extended Berkeley Packet Filter) and **XDP** (eXpress Data Path). By intercepting, analyzing, and dropping malicious traffic at the driver level—before it even enters the Linux kernel's standard TCP/IP stack—XDP-Firewall delivers massive throughput and near-zero-overhead mitigation against DDoS attacks and network abuse.

---

## 💡 What does this actually do? (In simple words)

If you have never worked with low-level firewalls before, here is the short version:

* **A normal firewall** (like `iptables` or `ufw`) inspects every packet *after* the Linux kernel has already processed it. That is slow and wastes CPU during attacks.
* **This firewall** hooks directly into the network card's driver. Packets are inspected and — if they are bad — dropped **before the kernel even looks at them**. The CPU never has to deal with them.
* The result: you can block floods, scans, and DDoS attacks with very little CPU usage, even on a small server.

You configure everything through a web dashboard. No command-line editing, no service restarts. Click a rule, it is live.

---

## 🌟 Core Architecture

XDP-Firewall is split into two parts that talk to each other through shared kernel memory (BPF maps):

### 1. Kernel Space (Data Plane) — `xdp_firewall.c`
The eBPF program hooks directly into the network interface.

* **O(1) & O(log N) Lookups:** Uses high-speed eBPF maps (`BPF_LPM_TRIE` for subnets/CIDR, `BPF_HASH` for ports and IPs) for immediate packet decisions.
* **Stateful Connection Tracking (Conntrack):** Tracks session states (`CT_NEW`, `CT_EST`) so return traffic of allowed connections is passed without re-evaluating your whole ruleset. Timeouts are protocol-aware: TCP 300 s (established) / 30 s (new), UDP 120 s, ICMP 30 s. Up to 131072 concurrent flows.
* **Multi-Tier Rate Limiting:** Precision rate limiting with a 1-second sliding window, entirely in the kernel. Global, per-protocol, per-IP, per-port, and per-IP-plus-port scopes.
* **IPv6 Policy Bit:** A simple on/off switch for IPv6 traffic (allow-all or drop-all) so a misconfigured IPv4 ruleset cannot silently break v6 management sessions.

### 2. User Space (Control Plane) — `backend.py`
A Python backend built on **FastAPI** and **BCC** (BPF Compiler Collection).

* **Live Map Synchronization:** Compiles and injects rules from `rules.json` into the kernel without restarts or recompilation. Rule changes are instant.
* **Secure Web Dashboard:** A pure HTML/JS frontend with zero runtime dependencies, served over HTTPS (Uvicorn). Live charts, instant rule toggling, dark/light mode, and real-time drop monitoring.
* **Safe Writes:** Rules are validated with Pydantic *before* any map is touched. The `rules.json` file is written atomically (temp file + `rename`) so a crash can never corrupt it.

---

## ✨ Key Features

* ⚡ **Line-Rate Packet Processing:** Drops bad packets at the lowest possible OSI Layer 2/3 boundary.
* 🔒 **Advanced Rate Limiting Engine:**
  * **Global PPS Limits:** Cap total packets per second across the whole server.
  * **Per-IP Limits:** Prevent single-source floods and brute-force attacks.
  * **Protocol/Port Specific:** Limit abusive ICMP echo requests, restrict SSH connection attempts, throttle DNS queries independently from responses.
* 🛡️ **Fail-Safe Installation:** `install.sh` detects the active SSH session and injects a safety rule for that IP *before* attaching the program — so you cannot lock yourself out during deployment.
* 🔑 **Secure by Default:**
  * Auto-generates a high-entropy API key for the web UI (`api_key.txt`, mode 0600).
  * Provisions a self-signed TLS certificate (`cert.pem`, `cert.key`) on first run.
  * HMAC-signed session cookies, per-IP brute-force throttling on login, and a restrictive Content-Security-Policy that forbids inline scripts.
* 📝 **Seven Rule Types in `rules.json`:**
  * `filter` — classic allow/block by source, protocol, port, ICMP type.
  * `established` — enables the conntrack fast path for return traffic.
  * `ratelimit` — global, per-protocol, or per-port PPS caps.
  * `ip_ratelimit` — per-source-IP caps, optionally scoped to a port.
  * `forward` — destination-port forwarding (via iptables DNAT).
  * `dns` — dedicated UDP/53 rules with independent request/response limits.
  * `conn_timeout` — overrides the default conntrack entry lifetime.
* 📊 **Live Dashboard:** Selectable 2 / 5 / 15-minute traffic window, dark + light theme, sparklines per counter, drop-reason breakdown (rate-limit / blocklist / ICMP / IPv6), full CRUD on rules with templates for the most common shapes (allow SSH, block port, per-IP rate limit, …).

---

## 🖼️ Dashboard and Performance

Measured throughput depends on NIC, driver, CPU, blocklist size, and active rate limiters. My 4-core server easily handles ≈700 kpps at only ≈29 % CPU load, so even a 4-core system can deal with 2M+ pps on suitable hardware. Driver-mode XDP (`XDP_DRV`) is significantly faster than generic mode (`XDP_SKB`) because it runs before `skb` allocation — confirm the active mode with `ip -details link show dev <iface>`.

<div align="center">
  <img width="800" height="443" alt="Dashboard Main View" src="https://github.com/user-attachments/assets/33037f52-4675-45e7-bca1-ce2506c26d00" />
  <img width="800" alt="Rule Management" src="https://github.com/user-attachments/assets/7bb5038b-863f-471b-aa47-741a75bcadb0" style="border-radius: 8px;" />
</div>

---

## 🚀 Installation & Deployment

### System Prerequisites
* **OS:** Linux distribution (Ubuntu 20.04 / 22.04 or Debian 11 / 12 highly recommended).
* **Kernel:** Version 5.4 or higher. 5.10+ recommended for stable generic-mode XDP.
* **Architecture:** x86_64 or aarch64.
* **Python:** 3.8 or newer.
* **Dependencies:** BCC (`bpfcc-tools`) and the kernel headers matching `uname -r` — both are installed automatically by the script.
* **Privileges:** `root` (sudo) access is mandatory to attach XDP programs to network interfaces.

### Automated Setup
The installation script handles dependency resolution, directory creation, certificate and API-key generation, an SSH safety rule, and systemd service registration.

```bash
# 1. Clone the repository
git clone https://github.com/pc10211/XDP-Firewall.git
cd XDP-Firewall

# 2. Make the installer executable
chmod +x install.sh

# 3. Run the installer as root
sudo ./install.sh
```

After installation the dashboard is available at **`https://<your-server>:8443/`**. The generated API key is printed to the journal and stored in `api_key.txt`.

```bash
# Service management
systemctl status xdp-firewall
systemctl restart xdp-firewall
journalctl -u xdp-firewall -f
```

---

## 📝 Example rule

Every rule in `rules.json` follows the same shape. This one allows SSH from anywhere but rate-limits each source IP to 20 packets per second — enough for a normal login, far too little for a brute-force attack:

```json
{
  "id":        "ssh-safety",
  "type":      "filter",
  "action":    "allow",
  "direction": "inbound",
  "src":       "any",
  "protocol":  "tcp",
  "dst_port":  "22",
  "per_ip_limit": 20,
  "comment":   "SSH (safety)",
  "enabled":   true,
  "priority":  1
}
```

You almost never have to edit this file by hand — the dashboard has a form for every field and a library of templates.

---

## 🔧 Useful commands

```bash
# Detach the firewall from an interface (emergency recovery)
ip link set dev <iface> xdp off

# Check whether XDP is attached and in which mode
ip -details link show dev <iface>

# Rotate the API key: delete it and restart; a new one is generated
rm api_key.txt && systemctl restart xdp-firewall && journalctl -u xdp-firewall | grep "API key"
```

---

## ⚠️ Limitations (be honest about what this is)

* **No IPv6 filtering yet.** The `ipv6_policy` bit is allow-all or drop-all; there is no IPv6 rule evaluation path.
* **No Layer-7 inspection.** Pure L2/L3/L4. No HTTP, TLS SNI, or DNS payload matching.
* **`forward` rules use iptables DNAT** in user space, so high-throughput port-forwarding is bound by netfilter rather than XDP.
* **One interface per process.** Run multiple instances to protect multiple NICs.
* **No clustering.** Each node is independent; there is no built-in state replication.

---

## 🆘 Troubleshooting

* **Dashboard shows "disconnected"** — the live stream (`text/event-stream`) is being buffered by a reverse proxy, or the service is not running. Check `systemctl status xdp-firewall`.
* **BCC fails to compile the BPF program** — install matching kernel headers: `apt install linux-headers-$(uname -r)`.
* **Legitimate traffic is dropped** — make sure the `established` rule type is enabled (conntrack fast path for return traffic), and check the drop-reason breakdown on the dashboard.
* **Locked out after a bad rule** — from a local console or IPMI session: `ip link set dev <iface> xdp off`. The rules in `rules.json` are not touched, so you can edit the file, restart, and re-apply.

---

## 📁 Project layout

```
XDP-Firewall/
├── backend.py          FastAPI control plane, BPF loader, HTTP API
├── xdp_firewall.c      eBPF data plane + tc_egress classifier
├── rules.json          Persistent rule set
├── index.html          Web dashboard (single file, no build step)
├── login.html          Login page
├── install.sh          System installer (systemd unit, deps, certs)
├── api_key.txt         Generated at first run, mode 0600
├── cert.pem / cert.key Generated at first run
└── session_secret.bin  Generated at first run
```

Contributions, bug reports and feature requests are welcome — please open an issue first for substantial changes, and include kernel version (`uname -r`), distribution, NIC model and driver when reporting a bug.

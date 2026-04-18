# 🛡️ XDP-Firewall v2.0

> **Enterprise-Grade eBPF/XDP Firewall**: Ultra-low latency kernel-level packet filtering with stateful connection tracking, advanced rate limiting, and an intuitive web management console.

Welcome to the **XDP-Firewall** repository. This project is engineered to provide bare-metal network protection by leveraging the raw power of **eBPF** (Extended Berkeley Packet Filter) and **XDP** (eXpress Data Path). By intercepting, analyzing, and dropping malicious traffic at the driver level—before it even enters the Linux kernel's standard TCP/IP stack—XDP-Firewall ensures massive throughput and zero-overhead mitigation against DDoS attacks and network abuse.

---

## 🌟 Core Architecture & Capabilities

XDP-Firewall bridges the gap between low-level kernel performance and user-friendly management through a two-tier architecture:

### 1. Kernel Space (Data Plane)
Written in strict C (`xdp_firewall.c`), the eBPF program hooks directly into the network interface.
* **O(1) & O(log N) Lookups:** Utilizes high-speed eBPF maps (`BPF_LPM_TRIE` for subnets/CIDR, `BPF_HASH` for ports and IPs) for immediate packet adjudication.
* **Stateful Connection Tracking (Conntrack):** Maintains session states (`CT_NEW`, `CT_EST`) to safely allow return traffic without re-evaluating complex rulesets.
* **Multi-Tier Rate Limiting:** Executes precision rate limiting using sliding-window tracking directly in the kernel memory, mitigating floods before they consume CPU cycles.

### 2. User Space (Control Plane)
A high-performance Python backend (`backend.py`) powered by **FastAPI** and **BCC** (BPF Compiler Collection).
* **Live Map Synchronization:** Dynamically compiles and injects rules from `rules.json` into kernel maps. No service restarts or kernel recompilations are required when updating your firewall policies.
* **Secure Web Dashboard:** A pure HTML/JS frontend with zero external dependencies, served via HTTPS (Uvicorn). Features live sparkline traffic charts, instant rule toggling, and real-time block event monitoring.

---

## ✨ Key Features

* ⚡ **Line-Rate Packet Processing:** Drops bad packets at the lowest possible OSI Layer 2/3 boundary.
* 🔒 **Advanced Rate Limiting Engine:** * **Global PPS Limits:** Cap total packets per second.
  * **Per-IP Limits:** Prevent single-source floods and brute-force attacks.
  * **Protocol/Port Specific:** Limit abusive ICMP echo requests or restrict SSH connection attempts.
* 🛡️ **Fail-Safe Installation:** The `install.sh` script automatically detects active SSH sessions and injects safety rules to prevent accidental lockouts during deployment.
* 🔑 **Secure by Default Design:** * Automatically generates high-entropy API keys for the web UI.
  * Provisions self-signed TLS certificates (`cert.pem`, `cert.key`) upon initialization.
  * Employs built-in brute-force protection on the login interface.
* 📝 **Extensible Rule Syntax (`rules.json`):** Granular control over inbound/outbound traffic, port forwarding, ICMP types, and connection timeouts.

---

## 🖼️ Dashboard and Performance:
    Measured throughput depends on NIC, driver, CPU, blocklist size, and active rate limiters. My 4 core server easy handelt 700k pps whit only 29% cpu load so already a 4 core system can handel 2m+ pps

<div align="center">
  <img width="1000" height="643" alt="grafik" src="https://github.com/user-attachments/assets/33037f52-4675-45e7-bca1-ce2506c26d00" />
  <img width="800" alt="Rule Management" src="https://github.com/user-attachments/assets/7bb5038b-863f-471b-aa47-741a75bcadb0" style="border-radius: 8px;" />
</div>

---

## 🚀 Installation & Deployment

### System Prerequisites
* **OS:** Linux distribution (Ubuntu 20.04/22.04 or Debian 11/12 highly recommended).
* **Kernel:** Version 5.4 or higher (supports eBPF and XDP).
* **Privileges:** `root` (sudo) access is mandatory to attach XDP programs to network interfaces.

### Automated Setup
The included installation script handles dependency resolution (Python 3, BCC tools, Linux headers), directory creation, and systemd service registration.

```bash
# 1. Clone the repository
git clone [https://github.com/pc10211/XDP-Firewall.git](https://github.com/pc10211/XDP-Firewall.git)
cd XDP-Firewall

# 2. Make the installer executable
chmod +x install.sh

# 3. Run the installer as root
sudo ./install.sh

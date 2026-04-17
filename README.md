# XDP-Firewall 1.1v

> Next-gen XDP Firewall: High-performance packet filtering with an intuitive web panel and built-in rate limiting.

Welcome to the XDP-Firewall repository. This project leverages the power of eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path) to drop malicious traffic at the lowest possible level in the Linux network stack, ensuring blazing-fast performance without compromising your system's resources.

---

## ✨ Features

* **Bare-Metal Performance:** Uses `xdp_firewall.c` to filter packets directly in the kernel before they even reach the standard network stack.
* **Interactive Web Panel:** A clean and responsive dashboard (`index.html`) to monitor traffic and manage your security posture in real-time.
* **Advanced Rate Limiting:** Built-in protection against DDoS attacks, brute-force attempts, and network abuse.
* **Dynamic Rule Engine:** Easily update blocklists, allowlists, and port rules via the `rules.json` file without needing to recompile the kernel code.
* **Seamless Backend Integration:** The `backend.py` script bridges the high-speed kernel space with the user-friendly web interface.
* **Automated Setup:** Get up and running in minutes with the included `install.sh` script.
<img width="900" height="990" alt="grafik" src="https://github.com/user-attachments/assets/d3feb273-67d5-47cb-935c-cfa5efb402d3" /><img width="748" height="358" alt="grafik" src="https://github.com/user-attachments/assets/7bb5038b-863f-471b-aa47-741a75bcadb0" />



---

## 🚀 Setup & Installation

### Prerequisites
* A Linux system with a modern kernel (5.4+ recommended) that supports eBPF/XDP.
* `root` (sudo) privileges to attach XDP programs to network interfaces.

### 1. Clone the Repository
Download the files to your server or local machine:
```bash
git clone [https://github.com/pc10211/XDP-Firewall.git](https://github.com/pc10211/XDP-Firewall.git)
cd XDP-Firewall

chmod +x install.sh
sudo ./install.sh

and boom your done 

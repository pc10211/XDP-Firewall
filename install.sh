#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Muss als root laufen"
    exit 1
fi

INSTALL_DIR="/opt/xdp-firewall"
SERVICE_NAME="xdp-firewall"
SERVICE_USER="root"
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
DEFAULT_IFACE=${DEFAULT_IFACE:-eth0}
PY_CMD=""

echo "==================================================="
echo " XDP Firewall Installation v5.1"
echo "==================================================="
echo ""

SSH_CLIENT_IP=""
if [ -n "$SSH_CONNECTION" ]; then
    SSH_CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    echo "[SSH-SAFETY] Installation läuft über SSH von $SSH_CLIENT_IP"
    echo "[SSH-SAFETY] Port 22 wird in Default-Regeln freigegeben."
    echo ""
fi

echo "[*] Installiere System-Abhängigkeiten..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    bpfcc-tools python3-bpfcc \
    linux-headers-$(uname -r) \
    iptables iproute2 \
    openssl \
    curl jq \
    2>&1 | grep -v "^$" || true

echo "[*] Erstelle Installationsverzeichnis: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp backend.py      "$INSTALL_DIR/"
cp xdp_firewall.c  "$INSTALL_DIR/"
cp index.html      "$INSTALL_DIR/"
cp login.html      "$INSTALL_DIR/"

if [ ! -f "$INSTALL_DIR/rules.json" ]; then
    cp rules.json "$INSTALL_DIR/"
    echo "[*] Default-Regeln (inkl. SSH:22) installiert"
else
    echo "[*] rules.json existiert bereits – NICHT überschrieben"
fi

chmod 600 "$INSTALL_DIR/rules.json" 2>/dev/null || true

echo "[*] Prüfe Python-Umgebung..."
if python3 -c "import fastapi, uvicorn, pydantic" 2>/dev/null; then
    PY_CMD="/usr/bin/python3"
    echo "    System-Python hat FastAPI/uvicorn/pydantic – wird genutzt"
    python3 -c "import cryptography" 2>/dev/null || pip3 install --break-system-packages cryptography 2>/dev/null || true
else
    echo "    Erstelle venv unter $INSTALL_DIR/venv"
    python3 -m venv --system-site-packages "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install --quiet fastapi uvicorn pydantic pyroute2 cryptography
    PY_CMD="$INSTALL_DIR/venv/bin/python3"
fi

echo "[*] Generiere TLS-Zertifikat (selbstsigniert, 10 Jahre gültig)..."
if [ ! -f "$INSTALL_DIR/cert.pem" ] || [ ! -f "$INSTALL_DIR/cert.key" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
        -days 3650 \
        -keyout "$INSTALL_DIR/cert.key" \
        -out    "$INSTALL_DIR/cert.pem" \
        -subj "/CN=xdp-firewall" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$INSTALL_DIR/cert.key"
    chmod 644 "$INSTALL_DIR/cert.pem"
    echo "    TLS-Zertifikat erstellt: $INSTALL_DIR/cert.pem"
else
    echo "    TLS-Zertifikat existiert bereits"
fi

echo "[*] Generiere API-Key (wenn nicht vorhanden)..."
if [ ! -f "$INSTALL_DIR/api_key.txt" ]; then
    openssl rand -hex 32 > "$INSTALL_DIR/api_key.txt"
    chmod 600 "$INSTALL_DIR/api_key.txt"
fi
API_KEY=$(cat "$INSTALL_DIR/api_key.txt")

echo "[*] Prüfe Kernel-Module..."
modprobe sch_clsact 2>/dev/null || echo "    sch_clsact nicht verfügbar (optional für Egress-TC)"
modprobe act_bpf    2>/dev/null || true
modprobe cls_bpf    2>/dev/null || true

echo "[*] Erstelle systemd Service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=XDP Firewall Service v5.1
After=network.target
Wants=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=XDP_IFACE=${DEFAULT_IFACE}
Environment=FW_USE_TLS=1
Environment=FW_HTTPS_PORT=8443
Environment=FW_HTTP_PORT=8000
Environment=PYTHONUNBUFFERED=1
ExecStart=${PY_CMD} ${INSTALL_DIR}/backend.py
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_RESOURCE
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

if systemctl is-active --quiet ${SERVICE_NAME}; then
    echo "[*] Service läuft bereits – restarte..."
    systemctl restart ${SERVICE_NAME}
else
    echo "[*] Aktiviere und starte Service..."
    systemctl enable ${SERVICE_NAME} >/dev/null 2>&1
    systemctl start ${SERVICE_NAME}
fi

sleep 2

if systemctl is-active --quiet ${SERVICE_NAME}; then
    SERVER_IP=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    SERVER_IP=${SERVER_IP:-localhost}

    echo ""
    echo "==================================================="
    echo " INSTALLATION ERFOLGREICH"
    echo "==================================================="
    echo ""
    echo "  Service:    ${SERVICE_NAME} (aktiv)"
    echo "  Interface:  ${DEFAULT_IFACE}"
    echo "  Web-UI:     https://${SERVER_IP}:8443/"
    echo ""
    echo "  API-Key:    ${API_KEY}"
    echo "  Gespeichert: ${INSTALL_DIR}/api_key.txt (chmod 600)"
    echo ""
    if [ -n "$SSH_CLIENT_IP" ]; then
        echo "  SSH-Safety: Port 22 (TCP) ist freigegeben."
        echo "              Deine SSH-Session sollte erhalten bleiben."
        echo ""
    fi
    echo "  Hinweis: Browser zeigt Zertifikat-Warnung (Self-Signed)."
    echo "           Das ist normal – klicke 'Erweitert' → 'Trotzdem fortfahren'."
    echo ""
    echo "  Logs:       journalctl -u ${SERVICE_NAME} -f"
    echo "  Stop:       systemctl stop ${SERVICE_NAME}"
    echo "  Uninstall:  systemctl disable --now ${SERVICE_NAME} && rm -rf ${INSTALL_DIR}"
    echo ""
    echo "==================================================="
else
    echo ""
    echo "FEHLER: Service konnte nicht gestartet werden"
    echo "Logs anzeigen: journalctl -u ${SERVICE_NAME} -n 50"
    exit 1
fi

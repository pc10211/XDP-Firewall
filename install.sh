#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
RST='\033[0m'

log()  { echo -e "${GRN}[✓]${RST} $*"; }
warn() { echo -e "${YLW}[!]${RST} $*"; }
err()  { echo -e "${RED}[✗]${RST} $*"; exit 1; }
info() { echo -e "${CYN}[i]${RST} $*"; }

INSTALL_DIR="/opt/xdp-firewall"
SERVICE_NAME="xdp-firewall"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_IFACE=""

banner() {
    echo ""
    echo -e "${CYN}╔══════════════════════════════════════════╗${RST}"
    echo -e "${CYN}║${RST}       XDP Firewall Installer        ${CYN}║${RST}"
    echo -e "${CYN}║${RST}          ${CYN}║${RST}"
    echo -e "${CYN}╚══════════════════════════════════════════╝${RST}"
    echo ""
}

detect_iface() {
    DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
    if [ -z "$DEFAULT_IFACE" ]; then
        DEFAULT_IFACE="eth0"
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "Bitte als root ausführen: sudo bash install.sh"
    fi
}

check_os() {
    if [ ! -f /etc/debian_version ]; then
        warn "Kein Debian/Ubuntu erkannt — Installation könnte fehlschlagen"
    fi
    info "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY | cut -d= -f2 | tr -d '\"' || echo 'unbekannt')"
    info "Kernel: $(uname -r)"
}

install_deps() {
    log "Aktualisiere Paketlisten..."
    apt-get update -qq

    log "Installiere System-Abhängigkeiten..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        bcc \
        python3-bcc \
        libbpf-dev \
        linux-headers-"$(uname -r)" \
        iproute2 \
        iptables \
        curl \
        2>/dev/null || true

    if ! dpkg -l | grep -q python3-bcc 2>/dev/null; then
        warn "python3-bcc nicht via apt verfügbar, versuche alternatives Paket..."
        apt-get install -y -qq bpfcc-tools python3-bpfcc 2>/dev/null || true
    fi

    if ! python3 -c "from bcc import BPF" 2>/dev/null; then
        warn "BCC Python-Modul nicht gefunden — wird beim Start benötigt"
        warn "Versuche: apt install python3-bpfcc oder pip install bcc"
    else
        log "BCC Python-Modul OK"
    fi
}

install_python_deps() {
    log "Erstelle Python Virtual-Environment..."
    python3 -m venv "${INSTALL_DIR}/venv" 2>/dev/null || true

    if [ -f "${INSTALL_DIR}/venv/bin/pip" ]; then
        PIP="${INSTALL_DIR}/venv/bin/pip"
    else
        PIP="pip3"
    fi

    log "Installiere Python-Pakete..."
    $PIP install --quiet --upgrade pip 2>/dev/null || true
    $PIP install --quiet \
        fastapi \
        uvicorn[standard] \
        pydantic \
        pyroute2 \
        2>/dev/null || \
    $PIP install --break-system-packages --quiet \
        fastapi \
        uvicorn[standard] \
        pydantic \
        pyroute2 \
        2>/dev/null || true

    if [ -f "${INSTALL_DIR}/venv/bin/python" ]; then
        PYTHON="${INSTALL_DIR}/venv/bin/python"
    else
        PYTHON="python3"
    fi

    for pkg in fastapi uvicorn pydantic pyroute2; do
        if $PYTHON -c "import $pkg" 2>/dev/null; then
            log "$pkg OK"
        else
            warn "$pkg konnte nicht installiert werden"
        fi
    done
}

copy_files() {
    log "Erstelle Verzeichnis ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    for f in backend.py xdp_firewall.c index.html; do
        if [ -f "${SCRIPT_DIR}/${f}" ]; then
            cp "${SCRIPT_DIR}/${f}" "${INSTALL_DIR}/${f}"
            log "Kopiert: ${f}"
        else
            err "Datei nicht gefunden: ${SCRIPT_DIR}/${f}"
        fi
    done

    if [ -f "${SCRIPT_DIR}/rules.json" ]; then
        if [ ! -f "${INSTALL_DIR}/rules.json" ]; then
            cp "${SCRIPT_DIR}/rules.json" "${INSTALL_DIR}/rules.json"
            log "Kopiert: rules.json"
        else
            info "rules.json existiert bereits — übersprungen"
        fi
    else
        if [ ! -f "${INSTALL_DIR}/rules.json" ]; then
            echo "[]" > "${INSTALL_DIR}/rules.json"
            log "Leere rules.json erstellt"
        fi
    fi

    chmod 600 "${INSTALL_DIR}/rules.json"
    chmod 644 "${INSTALL_DIR}/backend.py" "${INSTALL_DIR}/xdp_firewall.c" "${INSTALL_DIR}/index.html"
}

create_service() {
    detect_iface
    info "Standard-Interface: ${DEFAULT_IFACE}"

    if [ -f "${INSTALL_DIR}/venv/bin/uvicorn" ]; then
        EXEC_START="${INSTALL_DIR}/venv/bin/uvicorn backend:app --host 0.0.0.0 --port 8000"
        PYTHON_PATH="${INSTALL_DIR}/venv/bin/python"
    elif command -v uvicorn &>/dev/null; then
        EXEC_START="$(command -v uvicorn) backend:app --host 0.0.0.0 --port 8000"
        PYTHON_PATH="$(command -v python3)"
    else
        EXEC_START="/usr/bin/python3 -m uvicorn backend:app --host 0.0.0.0 --port 8000"
        PYTHON_PATH="/usr/bin/python3"
    fi

    log "Erstelle systemd Service..."
    cat > "${SERVICE_FILE}" <<UNIT
[Unit]
Description=XDP Firewall v5.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
Environment=XDP_IFACE=${DEFAULT_IFACE}
ExecStart=${EXEC_START}
Restart=always
RestartSec=3
LimitMEMLOCK=infinity
LimitNOFILE=65536
Nice=-20
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xdp-firewall

[Install]
WantedBy=multi-user.target
UNIT

    chmod 644 "${SERVICE_FILE}"
    log "Service erstellt: ${SERVICE_FILE}"

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" 2>/dev/null || true
    log "Service aktiviert (startet bei Boot)"
}

start_service() {
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log "Starte Service neu..."
        systemctl restart "${SERVICE_NAME}"
    else
        log "Starte Service..."
        systemctl start "${SERVICE_NAME}"
    fi

    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log "Service läuft!"
    else
        warn "Service konnte nicht starten — prüfe: journalctl -u ${SERVICE_NAME} -n 30"
    fi
}

show_info() {
    echo ""
    echo -e "${GRN}══════════════════════════════════════════${RST}"
    echo -e "${GRN}  Installation abgeschlossen!${RST}"
    echo -e "${GRN}══════════════════════════════════════════${RST}"
    echo ""

    local IP
    IP=$(ip -4 addr show "${DEFAULT_IFACE}" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    if [ -z "$IP" ]; then
        IP="<server-ip>"
    fi

    info "Web-UI:     http://${IP}:8000"
    info "Interface:  ${DEFAULT_IFACE}"
    info "Dateien:    ${INSTALL_DIR}/"

    if [ -f "${INSTALL_DIR}/api_key.txt" ]; then
        echo ""
        info "API-Key:    $(cat "${INSTALL_DIR}/api_key.txt")"
    else
        echo ""
        info "API-Key wird beim ersten Start generiert"
    fi

    echo ""
    info "Befehle:"
    echo "  sudo systemctl status ${SERVICE_NAME}    # Status"
    echo "  sudo systemctl restart ${SERVICE_NAME}   # Neustarten"
    echo "  sudo systemctl stop ${SERVICE_NAME}      # Stoppen"
    echo "  sudo journalctl -u ${SERVICE_NAME} -f    # Logs"
    echo ""
    info "Interface ändern:"
    echo "  sudo nano ${SERVICE_FILE}"
    echo "  # Environment=XDP_IFACE=eth0 ändern"
    echo "  sudo systemctl daemon-reload && sudo systemctl restart ${SERVICE_NAME}"
    echo ""
}

main() {
    banner
    check_root
    check_os
    install_deps
    install_python_deps
    copy_files
    create_service
    start_service
    show_info
}

main "$@"

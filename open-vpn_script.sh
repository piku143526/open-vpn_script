#!/bin/bash
# OpenVPN Installer Script (Enhanced)
# Author: Modified by ChatGPT for improved compatibility and safety

set -euo pipefail

############################
# Logging Functions
############################
log() { echo -e "\e[34m[INFO]\e[0m $*"; }
success() { echo -e "\e[32m[SUCCESS]\e[0m $*"; }
warn() { echo -e "\e[33m[WARNING]\e[0m $*"; }
error() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }

############################
# Trap errors
############################
trap 'error "Error on line $LINENO. Exiting."' ERR

############################
# Root Check
############################
[[ "$EUID" -ne 0 ]] && error "This installer must be run as root."

############################
# Detect OS and Version
############################
get_os() {
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        error "Cannot detect OS. /etc/os-release missing."
    fi
}

check_os_support() {
    case "$OS" in
        ubuntu) (( $(echo "$VER >= 20.04" | bc -l) )) || error "Ubuntu $VER not supported. Use 20.04+." ;;
        debian) (( $(echo "$VER >= 10" | bc -l) )) || error "Debian $VER not supported. Use 10+." ;;
        centos|almalinux|rocky) (( ${VER%%.*} >= 8 )) || error "$OS $VER not supported. Use 8+." ;;
        fedora) : ;; # Fedora always latest
        arch) : ;;   # Arch always rolling
        *) error "Unsupported OS: $OS $VER" ;;
    esac
}

############################
# Detect Public IP (IPv4 + IPv6)
############################
get_public_ip() {
    PUBLIC_IPv4=$(curl -4s https://ipinfo.io/ip || true)
    PUBLIC_IPv6=$(curl -6s https://ifconfig.co || true)

    if [[ -n "$PUBLIC_IPv4" ]]; then
        PUBLIC_IP="$PUBLIC_IPv4"
    elif [[ -n "$PUBLIC_IPv6" ]]; then
        PUBLIC_IP="[$PUBLIC_IPv6]"
    else
        warn "Unable to detect public IP. Using hostname fallback."
        PUBLIC_IP=$(hostname -I | awk '{print $1}')
    fi
    log "Detected Public IP: $PUBLIC_IP"
}

############################
# Detect Default Interface
############################
get_interface() {
    DEFAULT_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -n1 || echo "eth0")
    log "Using interface: $DEFAULT_IF"
}

############################
# Firewall Setup
############################
setup_firewall() {
    log "Configuring firewall rules..."
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-service=openvpn
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
    elif systemctl is-active --quiet ufw; then
        ufw allow 1194/udp
        ufw allow OpenSSH
        sed -i "/^# END OPENVPN RULES/ d" /etc/ufw/before.rules
        sed -i "/^# START OPENVPN RULES/ d" /etc/ufw/before.rules
        cat >> /etc/ufw/before.rules <<-EOF
# START OPENVPN RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_IF -j MASQUERADE
COMMIT
# END OPENVPN RULES
EOF
        ufw reload
    else
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_IF -j MASQUERADE
        iptables-save > /etc/iptables.rules
        cat > /etc/systemd/system/iptables-restore.service <<-EOF
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl enable iptables-restore
    fi
    success "Firewall configured."
}

############################
# Install Dependencies
############################
install_deps() {
    log "Installing dependencies..."
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get install -y openvpn easy-rsa curl iptables ;;
        centos|almalinux|rocky) dnf install -y epel-release && dnf install -y openvpn easy-rsa curl iptables ;;
        fedora) dnf install -y openvpn easy-rsa curl iptables ;;
        arch) pacman -Sy --noconfirm openvpn easy-rsa curl iptables ;;
    esac
    success "Dependencies installed."
}

############################
# PKI Setup
############################
setup_pki() {
    log "Setting up PKI..."
    EASYRSA_URL="https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.4/EasyRSA-3.2.4.tgz"
    mkdir -p /etc/openvpn/easy-rsa
    curl -sL "$EASYRSA_URL" | tar xz -C /etc/openvpn/easy-rsa --strip-components=1
    cd /etc/openvpn/easy-rsa

    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa build-server-full server nopass
    ./easyrsa build-client-full client nopass
    ./easyrsa gen-crl

    cp pki/ca.crt pki/private/ca.key pki/dh.pem \
       pki/issued/server.crt pki/private/server.key \
       pki/crl.pem /etc/openvpn
    chown nobody:nogroup /etc/openvpn/crl.pem
    success "PKI setup complete."
}

############################
# OpenVPN Server Config
############################
setup_server_conf() {
    log "Creating OpenVPN server config..."
    cat > /etc/openvpn/server.conf <<-EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
crl-verify crl.pem
auth SHA256
tls-crypt tls-crypt.key
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-GCM
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF
    success "Server configuration complete."
}

############################
# SELinux Adjustment
############################
configure_selinux() {
    if sestatus 2>/dev/null | grep -q "enabled"; then
        log "Configuring SELinux..."
        semanage port -a -t openvpn_port_t -p udp 1194 || true
    fi
}

############################
# Enable and Start OpenVPN
############################
enable_openvpn() {
    systemctl enable --now openvpn@server
    systemctl status openvpn@server --no-pager || true
    success "OpenVPN service enabled and running."
}

############################
# Main
############################
main() {
    get_os
    check_os_support
    get_public_ip
    get_interface
    install_deps
    setup_pki
    setup_server_conf
    setup_firewall
    configure_selinux
    enable_openvpn
    success "OpenVPN installation complete. Public IP: $PUBLIC_IP"
}

main "$@"

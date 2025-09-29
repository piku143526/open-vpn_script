Here's an updated version of the OpenVPN installation script with several improvements:

```bash
#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2013 Nyr. Released under the MIT License.

# Script version
SCRIPT_VERSION="2.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handling
set -euo pipefail
trap 'log_error "Script failed at line $LINENO. Check previous messages for details."' ERR

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    log_error 'This installer needs to be run with "bash", not "sh".'
    exit 1
fi

# Discard stdin. Needed when running from a one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    os="centos"
    os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    group_name="nobody"
elif [[ -e /etc/arch-release ]]; then
    os="arch"
    group_name="nobody"
else
    log_error "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora, and Arch Linux."
    exit 1
fi

# OS version checks
if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
    log_error "Ubuntu 20.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
    exit 1
fi

if [[ "$os" == "debian" ]]; then
    if grep -q '/sid' /etc/debian_version; then
        log_warning "Debian Testing and Debian Unstable are not officially supported by this installer."
        read -p "Continue anyway? [y/N]: " continue_unsupported
        if [[ ! "$continue_unsupported" =~ ^[yY]$ ]]; then
            exit 1
        fi
    fi
    if [[ "$os_version" -lt 10 ]]; then
        log_error "Debian 10 or higher is required to use this installer.
This version of Debian is too old and unsupported."
        exit 1
    fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
    os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
    log_error "$os_name 8 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
    exit 1
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
    log_warning '$PATH does not include sbin. Try using "su -" instead of "su".'
    read -p "Continue anyway? [y/N]: " continue_path
    if [[ ! "$continue_path" =~ ^[yY]$ ]]; then
        exit 1
    fi
fi

if [[ "$EUID" -ne 0 ]]; then
    log_error "This installer needs to be run with superuser privileges."
    exit 1
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
    log_error "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
    exit 1
fi

# Store the absolute path of the directory where the script is located
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to install packages
install_packages() {
    local packages=$1
    log_info "Installing packages: $packages"
    
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get update
        apt-get install -y --no-install-recommends $packages
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        if [[ "$os" == "centos" ]]; then
            dnf install -y epel-release
        fi
        dnf install -y $packages
    elif [[ "$os" == "arch" ]]; then
        pacman -Sy --noconfirm $packages
    fi
}

# Function to get public IP
get_public_ip() {
    local ip_services=(
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://icanhazip.com"
        "http://ip1.dynupdate.no-ip.com"
    )
    
    for service in "${ip_services[@]}"; do
        public_ip=$(curl -s -m 5 "$service" 2>/dev/null || wget -T 5 -t 1 -qO- "$service" 2>/dev/null)
        if [[ -n "$public_ip" && "$public_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            echo "$public_ip"
            return 0
        fi
    done
    echo ""
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
        if [[ $i1 -le 255 && $i2 -le 255 && $i3 -le 255 && $i4 -le 255 ]]; then
            return 0
        fi
    fi
    return 1
}

# Function to setup firewall
setup_firewall() {
    local port=$1
    local protocol=$2
    local ip=$3
    local ip6=${4:-}
    
    if systemctl is-active --quiet firewalld.service; then
        log_info "Configuring firewalld..."
        firewall-cmd --add-port="$port"/"$protocol"
        firewall-cmd --zone=trusted --add-source=10.8.0.0/24
        firewall-cmd --permanent --add-port="$port"/"$protocol"
        firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
        
        if [[ -n "$ip6" ]]; then
            firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
            firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
            firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
            firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
        fi
        
    elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
        log_info "Configuring UFW..."
        ufw allow "$port"/"$protocol"
        # Add NAT rules for UFW
        sed -i '/^# START OPENVPN RULES/,/^# END OPENVPN RULES/d' /etc/ufw/before.rules
        cat >> /etc/ufw/before.rules <<EOF
# START OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from OpenVPN client to eth0
-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
EOF
        # Enable IP forwarding
        sed -i 's/^#*net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/ufw/sysctl.conf
        ufw reload
        
    else
        log_info "Configuring iptables..."
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)
        
        # nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
        # if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
        if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
            iptables_path=$(command -v iptables-legacy)
            ip6tables_path=$(command -v ip6tables-legacy)
        fi
        
        cat > /etc/systemd/system/openvpn-iptables.service <<EOF
[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -w 5 -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -w 5 -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
        
        if [[ -n "$ip6" ]]; then
            cat >> /etc/systemd/system/openvpn-iptables.service <<EOF
ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
        fi
        
        cat >> /etc/systemd/system/openvpn-iptables.service <<EOF
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
        
        systemctl enable --now openvpn-iptables.service
    fi
}

# Main installation
if [[ ! -e /etc/openvpn/server/server.conf ]]; then
    # Detect some Debian minimal setups where neither wget nor curl are installed
    if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
        log_warning "Wget or curl is required to use this installer."
        read -n1 -r -p "Press any key to install curl and continue..."
        install_packages "curl"
    fi
    
    clear
    echo -e "${GREEN}"
    cat << "EOF"
   ____   _   _   _   _  _  _   _   _   _   _   _  
  / __ \ | | | | | | | | | | | | | | | | | | | | | 
 | |  | || | | | | | | | | | | | | | | | | | | | | 
 | |  | || | | | | | | | | | | | | | | | | | | | | 
 | |__| || |_| | | |_| | | | | | |_| | | |_| | | | 
  \____/  \___/   \___/  |_| |_| \___/   \___/  |_| 
EOF
    echo -e "${NC}"
    echo 'Welcome to this OpenVPN road warrior installer!'
    echo "Script version: $SCRIPT_VERSION"
    echo
    
    # If system has a single IPv4, it is selected automatically. Else, ask the user
    if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        log_info "Automatically selected IP: $ip"
    else
        number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
        echo
        echo "Which IPv4 address should be used?"
        ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
        read -p "IPv4 address [1]: " ip_number
        until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
            echo "$ip_number: invalid selection."
            read -p "IPv4 address [1]: " ip_number
        done
        [[ -z "$ip_number" ]] && ip_number="1"
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
    fi
    
    # If $ip is a private IP address, the server must be behind NAT
    if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo
        log_info "This server is behind NAT. What is the public IPv4 address or hostname?"
        # Get public IP
        get_public_ip=$(get_public_ip)
        if [[ -n "$get_public_ip" ]]; then
            read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
        else
            read -p "Public IPv4 address / hostname: " public_ip
        fi
        
        # If the checkip service is unavailable and user didn't provide input, ask again
        until [[ -n "$public_ip" ]]; do
            log_error "Invalid input."
            read -p "Public IPv4 address / hostname: " public_ip
        done
        [[ -z "$public_ip" && -n "$get_public_ip" ]] && public_ip="$get_public_ip"
    fi
    
    # If system has a single IPv6, it is selected automatically
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
        log_info "Automatically selected IPv6: $ip6"
    fi
    
    # If system has multiple IPv6, ask the user to select one
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
        number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
        echo
        echo "Which IPv6 address should be used?"
        ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
        read -p "IPv6 address [1]: " ip6_number
        until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
            echo "$ip6_number: invalid selection."
            read -p "IPv6 address [1]: " ip6_number
        done
        [[ -z "$ip6_number" ]] && ip6_number="1"
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
    fi
    
    echo
    echo "Which protocol should OpenVPN use?"
    echo "   1) UDP (recommended)"
    echo "   2) TCP"
    read -p "Protocol [1]: " protocol
    until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
        echo "$protocol: invalid selection."
        read -p "Protocol [1]: " protocol
    done
    case "$protocol" in
        1|"") 
            protocol=udp
            ;;
        2) 
            protocol=tcp
            ;;
    esac
    
    echo
    echo "What port should OpenVPN listen on?"
    read -p "Port [1194]: " port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: invalid port."
        read -p "Port [1194]: " port
    done
    [[ -z "$port" ]] && port="1194"
    
    echo
    echo "Select a DNS server for the clients:"
    echo "   1) Default system resolvers"
    echo "   2) Google"
    echo "   3) 1.1.1.1 (Cloudflare)"
    echo "   4) OpenDNS"
    echo "   5) Quad9"
    echo "   6) Gcore"
    echo "   7) AdGuard"
    echo "   8) Specify custom resolvers"
    read -p "DNS server [1]: " dns
    until [[ -z "$dns" || "$dns" =~ ^[1-8]$ ]]; do
        echo "$dns: invalid selection."
        read -p "DNS server [1]: " dns
    done
    [[ -z "$dns" ]] && dns="1"
    
    # If the user selected custom resolvers, we deal with that here
    if [[ "$dns" = "8" ]]; then
        echo
        until [[ -n "$custom_dns" ]]; do
            echo "Enter DNS servers (one or more IPv4 addresses, separated by commas or spaces):"
            read -p "DNS servers: " dns_input
            # Convert comma delimited to space delimited
            dns_input=$(echo "$dns_input" | tr ',' ' ')
            # Validate and build custom DNS IP list
            for dns_ip in $dns_input; do
                if validate_ip "$dns_ip"; then
                    if [[ -z "$custom_dns" ]]; then
                        custom_dns="$dns_ip"
                    else
                        custom_dns="$custom_dns $dns_ip"
                    fi
                else
                    log_error "Invalid IP address: $dns_ip"
                    custom_dns=""
                    break
                fi
            done
        done
    fi
    
    echo
    echo "Enter a name for the first client:"
    read -p "Name [client]: " unsanitized_client
    # Allow a limited set of characters to avoid conflicts
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
    [[ -z "$client" ]] && client="client"
    
    echo
    echo "OpenVPN installation is ready to begin."
    echo "Summary of configuration:"
    echo "  IP: $ip"
    [[ -n "$public_ip" ]] && echo "  Public IP/Hostname: $public_ip"
    [[ -n "$ip6" ]] && echo "  IPv6: $ip6"
    echo "  Protocol: $protocol"
    echo "  Port: $port"
    echo "  Client name: $client"
    
    # Install a firewall if firewalld or iptables are not already available
    firewall=""
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null && ! command -v ufw >/dev/null 2>&1; then
        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            firewall="firewalld"
            log_info "firewalld will be installed and enabled."
        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            firewall="iptables"
        fi
    fi
    
    read -n1 -r -p "Press any key to continue..."
    
    # If running inside a container, disable LimitNPROC to prevent conflicts
    if systemd-detect-virt -cq; then
        mkdir -p /etc/systemd/system/openvpn-server@server.service.d/
        echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
    fi
    
    # Install OpenVPN and dependencies
    log_info "Installing OpenVPN and dependencies..."
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        install_packages "openvpn openssl ca-certificates $firewall"
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        install_packages "openvpn openssl ca-certificates tar $firewall"
    elif [[ "$os" == "arch" ]]; then
        install_packages "openvpn openssl ca-certificates"
    fi
    
    # If firewalld was just installed, enable it
    if [[ "$firewall" == "firewalld" ]]; then
        systemctl enable --now firewalld.service
    fi
    
    # Get easy-rsa
    log_info "Setting up easy-rsa..."
    easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.4/EasyRSA-3.2.4.tgz'
    mkdir -p /etc/openvpn/server/easy-rsa/
    { curl -sL "$easy_rsa_url" 2>/dev/null || wget -qO- "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
    chown -R root:root /etc/openvpn/server/easy-rsa/
    cd /etc/openvpn/server/easy-rsa/
    
    # Create the PKI, set up the CA and create TLS key
    ./easyrsa --batch init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa gen-tls-crypt-key
    
    # Create the DH parameters file using the predefined ffdhe2048 group
    echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
    
    # Make easy-rsa aware of our external DH file (prevents a warning)
    ln -sf /etc/openvpn/server/dh.pem pki/dh.pem
    
    # Create certificates and CRL
    ./easyrsa --batch --days=3650 build-server-full server nopass
    ./easyrsa --batch --days=3650 build-client-full "$client" nopass
    ./easyrsa --batch --days=3650 gen-crl
    
    # Move the stuff we need
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
    cp pki/private/easyrsa-tls.key /etc/openvpn/server/tc.key
    
    # CRL is read with each client connection, while OpenVPN is dropped to nobody
    chown nobody:"$group_name" /etc/openvpn/server/crl.pem
    # Without +x in the directory, OpenVPN can't run a stat() on the CRL file
    chmod o+x /etc/openvpn/server/
    
    # Generate server.conf
    log_info "Generating server configuration..."
    cat > /etc/openvpn/server/server.conf <<EOF
local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0
EOF
    
    # IPv6
    if [[ -n "$ip6" ]]; then
        echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
        echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    else
        echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    fi
    
    cat >> /etc/openvpn/server/server.conf <<EOF
ifconfig-pool-persist ipp.txt
EOF
    
    # DNS
    case "$dns" in
        1|"")
            # Locate the proper resolv.conf
            # Needed for systems running systemd-resolved
            if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
                resolv_conf="/etc/resolv.conf"
            else
                resolv_conf="/run/systemd/resolve/resolv.conf"
            fi
            # Obtain the resolvers from resolv.conf and use them for OpenVPN
            grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
                echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
            done
            ;;
        2)
            echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
            ;;
        3)
            echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
            ;;
        4)
            echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
            ;;
        5)
            echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
            ;;
        6)
            echo 'push "dhcp-option DNS 95.85.95.85"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 2.56.220.2"' >> /etc/openvpn/server/server.conf
            ;;
        7)
            echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
            echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
            ;;
        8)
            for dns_ip in $custom_dns; do
                echo "push \"dhcp-option DNS $dns_ip\"" >> /etc/openvpn/server/server.conf
            done
            ;;
    esac
    
    cat >> /etc/openvpn/server/server.conf <<EOF
push "block-outside-dns"
keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem
EOF
    
    if [[ "$protocol" = "udp" ]]; then
        echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
    fi
    
    # Enable net.ipv4.ip_forward for the system
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
    # Enable without waiting for a reboot or service restart
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    if [[ -n "$ip6" ]]; then
        # Enable net.ipv6.conf.all.forwarding for the system
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
        # Enable without waiting for a reboot or service restart
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi
    
    # Setup firewall
    setup_firewall "$port" "$protocol" "$ip" "$ip6"
    
    # If SELinux is enabled and a custom port was selected, we need this
    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
        # Install semanage if not already present
        if ! hash semanage 2>/dev/null; then
            if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                dnf install -y policycoreutils-python-utils
            elif [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
                apt-get install -y policycoreutils-python-utils
            fi
        fi
        semanage port -a -t openvpn_port_t -p "$protocol" "$port" 2>/dev/null || \
        semanage port -m -t openvpn_port_t -p "$protocol" "$port"
    fi
    
    # If the server is behind NAT, use the correct IP address
    [[ -n "$public_ip" ]] && ip="$public_ip"
    
    # client-common.txt is created so we have a template to add further users later
    cat > /etc/openvpn/server/client-common.txt <<EOF
client
dev tun
proto $

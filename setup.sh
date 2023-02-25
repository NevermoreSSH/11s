#!/bin/bash
    dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
    biji=`date +"%Y-%m-%d" -d "$dateFromServer"`

    BURIQ () {
        curl -sS https://raw.githubusercontent.com/NevermoreSSH/11s/main/member/allow > /root/tmp
        data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
        for user in "${data[@]}"
        do
        exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
        d1=(`date -d "$exp" +%s`)
        d2=(`date -d "$biji" +%s`)
        exp2=$(( (d1 - d2) / 86400 ))
        if [[ "$exp2" -le "0" ]]; then
        echo $user > /etc/.$user.ini
        else
        rm -f  /etc/.$user.ini > /dev/null 2>&1
        fi
        done
        rm -f  /root/tmp
}

    MYIP=$(curl -sS ipv4.icanhazip.com)
    Name=$(curl -sS https://raw.githubusercontent.com/NevermoreSSH/11s/main/member/allow | grep $MYIP | awk '{print $2}')
    echo $Name > /usr/local/etc/.$Name.ini
    CekOne=$(cat /usr/local/etc/.$Name.ini)

    Bloman () {
    if [ -f "/etc/.$Name.ini" ]; then
    CekTwo=$(cat /etc/.$Name.ini)
        if [ "$CekOne" = "$CekTwo" ]; then
            res="Expired"
        fi
    else
    res="Permission Accepted..."
    fi
}

    PERMISSION () {
        MYIP=$(curl -sS ipv4.icanhazip.com)
        IZIN=$(curl -sS https://raw.githubusercontent.com/NevermoreSSH/11s/main/member/allow | awk '{print $4}' | grep $MYIP)
        if [ "$MYIP" = "$IZIN" ]; then
        Bloman
        else
        res="Permission Denied!"
        fi
        BURIQ
}

    if [ "${EUID}" -ne 0 ]; then
            echo "You need to run this script as root"
            exit 1
    fi
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
            echo "OpenVZ is not supported"
            exit 1
    fi
    red='\e[1;31m'
    green='\e[0;32m'
    yell='\e[1;33m'
    tyblue='\e[1;36m'
    NC='\e[0m'
    purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
    tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
    yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
    green() { echo -e "\\033[32;1m${*}\\033[0m"; }
    red() { echo -e "\\033[31;1m${*}\\033[0m"; }
    cd /root


# Start Izin
    echo -ne "[ ${green}INFO${NC} ] Check permission : "

    PERMISSION
    if [ -f /home/needupdate ]; then
    red "Your script need to update first !"
    exit 0
    elif [ "$res" = "Permission Accepted..." ]; then
    green "Permission Accepted!"
    else
    red "Permission Denied!"
    rm setup.sh > /dev/null 2>&1
    sleep 10
    exit 0
    fi
    sleep 2

# REPO    
    REPO="https://raw.githubusercontent.com/NevermoreSSH/11s/main/"

# Buat direktori xray
    mkdir -p /etc/xray
    mkdir -p /root/akun
    mkdir -p /root/akun/vmess
    mkdir -p /root/akun/vless
    mkdir -p /root/akun/trojan
    mkdir -p /root/akun/shadowsocks
    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ifconfig.me > /etc/xray/ipvps
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp
    curl -s ${REPO}xray/version | cut -d " " -f 2-10 >> /etc/xray/version
    touch /etc/xray/domain
    mkdir -p /var/log/xray
    chown www-data.www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    mkdir -p /var/lib/firdaus >/dev/null 2>&1
    echo "IP=" >> /var/lib/firdaus/ipvps.conf

# Change Environment System
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
}

# Update and remove packages
function base_package() {
    sudo apt-get autoremove -y man-db apache2 ufw exim4 firewalld -y
    sudo add-apt-repository ppa:vbernat/haproxy-2.7 -y
    sudo apt update && apt upgrade -y
    sudo apt-get install -y --no-install-recommends software-properties-common
    sudo apt install squid nginx zip pwgen openssl netcat socat cron bash-completion \
    curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils \
    tar wget curl ruby zip unzip p7zip-full python3-pip haproxy libc6 util-linux build-essential \
    msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent \
    net-tools  jq openvpn easy-rsa python3-certbot-nginx -y
    sudo apt-get autoremove -y
    apt-get clean all
}

# Fungsi input domain
function pasang_domain() {
    yellow "Tambah Domain Untuk Server Nginx, Xray Server"
    sleep 2
    read -rp "Input ur domain : " -e pp
    if [ -z $pp ]; then
        echo -e "
        Nothing input for domain!
        Then a random domain will be created"
    else
    echo "$pp" > /etc/xray/domain
    echo $pp > /root/domain
        echo "IP=$pp" > /var/lib/firdaus/ipvps.conf
    fi
}

# Pasang SSL
function pasang_ssl() {
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /etc/xray/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
}

#Instal Xray
function install_xray() {
    apt install iptables iptables-persistent -y
    apt install chrony -y
    systemctl enable chronyd
    systemctl restart chronyd
    systemctl enable chrony
    systemctl restart chrony
    chronyc sourcestats -v
    chronyc tracking -v
    apt install xz-utils apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
    apt install ntpdate -y
    ntpdate pool.ntp.org
    apt install zip -y
    
    # install xray
    #echo -e "[ ${green}INFO$NC ] Downloading & Installing xray core"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # / / Ambil Xray Core Version Terbaru
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version ${version}
 
    # // Ambil Config Server
    wget -O /etc/xray/config.json "${REPO}xray/config.json" >/dev/null 2>&1 
    wget -O /etc/systemd/system/runn.service "${REPO}xray/runn.service" >/dev/null 2>&1 
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    
    # Settings UP Nginix Server
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}xray/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl https://raw.githubusercontent.com/NevermoreSSH/11s/main/ssh/nginx.conf > /etc/nginx/nginx.conf

    # > Set Permission
    chmod +x /etc/systemd/system/runn.service

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com/firdaus-rx
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
}

function ssh(){
    # Install ssh
    wget ${REPO}ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && screen -S ssh-vpn ./ssh-vpn.sh
 
    # Install ssh-ws
    wget ${REPO}ssh-ws/ssh-ws.sh && chmod +x ssh-ws.sh && screen -S ssh-ws ./ssh-ws.sh

    # Install ssh-ohp
    wget ${REPO}ssh/ohp.sh && chmod +x ohp.sh && screen -S ohp.sh ./ohp.sh
}

#Instal Menu
function menu(){
    clear
    wget -O ~/menu-main.zip "${REPO}menu/menu.zip" >/dev/null 2>&1
    mkdir /root/menu
    7z e  ~/menu-main.zip -o/root/menu/ >/dev/null 2>&1
    chmod +x /root/menu/*
    mv /root/menu/* /usr/bin/
}

# Membaut Default Menu 
function profile(){
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

echo "0 5 * * * root clearlog && reboot" >> /etc/crontab
echo "0 0 * * * root xp" >> /etc/crontab
echo "0 1 * * * root delexp" >> /etc/crontab
echo "10 4 * * * root clearlog && sslh-fix-reboot" >> /etc/crontab
echo "0 0 * * * root clearlog && reboot" >> /etc/crontab
echo "0 12 * * * root clearlog && reboot" >> /etc/crontab
echo "0 18 * * * root clearlog && reboot" >> /etc/crontab

chmod 644 /root/.profile

echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
service cron restart
cat >/home/daily_reboot <<EOF
5
EOF

cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local

}

# Restart layanan after install
function enable_services(){
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
}

# Fingsi Install Script
function instal(){
    first_setup
    base_package
    pasang_domain
    pasang_ssl
    install_xray
    ssh
    menu
    profile
    enable_services
    log_install  >> /root/log-install.txt
}

function log_install(){
    echo ""
    echo "   >>> Service & Port"          
    echo "   - SlowDNS                       : All Port SSH "
    echo "   - OpenSSH                       : 22, 2253 "
    echo "   - Dropbear                      : 443, 109, 143, 1153 "
    echo "   - Stunnel5                      : 443, 445, 777 "
    echo "   - OpenVPN                       : TCP 1194, UDP 2200, SSL 990"
    echo "   - Websocket SSH TLS             : 443 "
    echo "   - Websocket SSH HTTP            : 8880 "
    echo "   - Websocket OpenVPN             : 2086 "
    echo "   - Squid Proxy                   : 3128, 8080 [OFF]"
    echo "   - Badvpn                        : 7100, 7200, 7300"
    echo "   - Nginx   	    	             : 81"
    echo "   - Vmess TLS	    	         : 8443"
    echo "   - Vmess None TLS	             : 80"
    echo "   - Vless TLS	         	     : 8443"
    echo "   - Vless None TLS	             : 80"
    echo "   - Trojan GRPC	                 : 8443"
    echo "   - Trojan WS		             : 8443"
    echo "   - Sodosok WS/GRPC               : 8443"
    echo "" 
    echo "   >>> Server Information & Other Features" 
    echo "   - Timezone	         	         : Asia/Jakarta (GMT +7)" 
    echo "   - Auto Remove Experied Account  : [ON]"
    echo "   - IPtables		                 : [ON]" 
    echo "   - IPv6			                 : [ON]" 
    echo "   - Auto Reboot                   : [ON]" 
    echo "   - Full Orders For Various Services"
    echo ""
    echo -e ""

}
instal
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
echo -ne "[ ${yell}WARNING${NC} ] Mulai Ulang Sekarang ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
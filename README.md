## Service & Port"          

- SlowDNS                       : All Port SSH
- OpenSSH                       : 22, 2253 
- Dropbear                      : 443, 109, 143, 1153 
- Stunnel5                      : 443, 445, 777 
- OpenVPN                       : TCP 1194, UDP 2200, SSL 990
- Websocket SSH TLS             : 443 
- Websocket SSH HTTP            : 8880 
- Websocket OpenVPN             : 2086 
- Squid Proxy                   : 3128, 8080 [OFF]
- Badvpn                        : 7100, 7200, 7300
- Nginx   	    	            : 81
- Vmess TLS	    	            : 8443
- Vmess None TLS	            : 80
- Vless TLS	                    : 8443
- Vless None TLS	            : 80
- Trojan GRPC	                : 8443
- Trojan WS		                : 8443
- Sodosok WS/GRPC               : 8443

```
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget https://raw.githubusercontent.com/NevermoreSSH/11s/main/setup.sh && chmod +x setup.sh && sed -i -e 's/\r$//' setup.sh && screen -S setup ./setup.sh
```
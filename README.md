# WSVPN - OpenVPN over websocket

![slika](https://user-images.githubusercontent.com/3339198/236639256-127d78c7-785d-4f0c-93c3-19534977d8b5.png)

## Instalation on Debian/Ubuntu server

### Install dependencies
First, install dependencies:
`sudo apt install python3-psutil python3-openssl python3-tornado`

## Setting up Nginx

The next step is to set up Nginx webserver to be able to handle websocket connections.

First we open our website config:
`sudo nano /etc/nginx/sites-enabled/default`

...and add these lines:

```
    ## WebSocket proxy where WSVPN is listening for incoming connections
    location /ws/vpn/ {
        proxy_pass http://127.0.0.1:2000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
```

In this example Nginx will be accepting websocket connections on location `/ws/vpn/` and pass them to localhost `127.0.0.1` to port `2000`, where WSVPN server will be listening.

### Setting up OpenVPN WS server

If you have already OpenVPN server running, you need another instance of it, with different settings.

`sudo nano /etc/openvpn/Telefoncek_WS.conf`

The most important settings are:

```
# OpenVPN WS server is listening on localhost
local 127.0.0.1     

# OpenVPN WS server is listening on TCP port 8081
proto tcp4
port 8081

# We are using tun1 virtual network interface (if other OpenVPN instance is using tun0) 
dev tun1

# Allocation of local IP addresses (should be different from other OpenVPN instances)
server 10.10.7.0 255.255.255.0

# OpenVPN WS server is used as gateway to the internet
push "redirect-gateway def1"

# Set up DNS servers to be pushed to the clients
push "dhcp-option DNS 8.8.8.8"

# If we use our own DNS server (e.g. PiHole), we can push this DNS to the clients instead 
push "dhcp-option DNS 10.10.8.1"

status /var/log/openvpn/status_ws.log
log /var/log/openvpn/openvpn_ws.log
log-append /var/log/openvpn/openvpn_ws.log
```

If you are using static client IP adresses, you can setup `client-config-dir`.

### Setup UFW rules

In the `ufw` configuration `sudo nano /etc/ufw/before.rules` add postrouting rule before `*filter` line:

```
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.10.7.0/24 -o ens3 -j MASQUERADE
-A POSTROUTING -s 10.10.8.0/24 -o ens3 -j MASQUERADE
COMMIT
```
In this example, we have configuration for two OpenVPN instances, one is WS one (using network `10.10.7.0/24`) and the other is normal OpenVPN (using network `10.10.8.0/24`).

Please note you need to restart `ufw` or the whole server in order to this changes come into effect.

You can also allow `ssh` connections to the server from the OpenVPN WS network:

`sudo ufw allow from 10.10.7.0/24 to any port 22 proto tcp`

#### Activate OpenVPN WS server

Now we start up the service and enable it on startup:

```
sudo systemctl start openvpn@Telefoncek_WS.service
sudo systemctl enable openvpn@Telefoncek_WS.service
```

### Run WSVPN in server mode 

Finally, we create a folder (`mkdir wsvpn`) and copy WSVPN Python script to it.

The we run it in `screen`, so it stays active in background:

```
screen -S WSVPN-server /usr/bin/python3 /home/matej/wsvpn/wsvpn3.py -m server -l ws://127.0.0.1:2000/ws/vpn/ -u localhost:8081 -d
```

The script will be accepting websocket connections from Nginx on localhost, on TCP port `2000`, and pass it to OpenVPN listening on localhost on TCP port `8081`.

You will get the printout:
```
[2023-05-06 20:04:29,105 INFO] WSVPN VPN Websocket Proxy v1.10
[2023-05-06 20:04:29,105 INFO] Copyright (c) 2017-2022 Matej Kovacic, Gasper Zejn, Matjaz Rihtar
[2023-05-06 20:04:29,106 DEBUG] Using selector: EpollSelector
[2023-05-06 20:04:29,109 INFO] Server listening on ws://127.0.0.1:2000/ws/vpn/
[2023-05-06 20:04:29,109 INFO] Will proxy requests to ws://localhost:8081/
```

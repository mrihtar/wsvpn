# WSVPN - OpenVPN over websocket

![WSVPN schema](https://user-images.githubusercontent.com/3339198/236639256-127d78c7-785d-4f0c-93c3-19534977d8b5.png)

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

## Installation on client (Ubuntu 22.10)

### Install dependencies
First, install dependencies:
`sudo apt install python3-psutil python3-openssl python3-tornado`

### Run WSVPN in client mode 

Now we create a folder (`mkdir WSVPN`), copy WSVPN Python script to it and run it with `sudo` privileges:

```
sudo /usr/bin/python3 /home/matej/WSVPN/wsvpn3.py -m client -l 127.0.0.1:8000 -u wss://telefoncek.si:443/ws/vpn/ -r
```
In this example, WSVPN script will open HTTPS encrypted (port `443`) websocket connection to telefoncek.si/ws/vpn/. To that entpoint will then be forwarded all TCP network traffic received from `localhost`, port `8000`.

We get the printout:
```
[2023-05-06 20:10:34,355 INFO] WSVPN VPN Websocket Proxy v1.10
[2023-05-06 20:10:34,355 INFO] Copyright (c) 2017-2022 Matej Kovacic, Gasper Zejn, Matjaz Rihtar
[2023-05-06 20:10:34,466 INFO] Running cmd: ip route
[2023-05-06 20:10:34,466 ERROR] /usr/lib/python3.10/subprocess.py:959: RuntimeWarning: line buffering (buffering=1) isn't supported in binary mode, the default buffer size will be used
[2023-05-06 20:10:34,467 ERROR]   self.stdout = io.open(c2pread, 'rb', bufsize)
[2023-05-06 20:10:34,468 CRITICAL] run_cmd(212): AttributeError: module 'sys' has no attribute 'maxint'
[2023-05-06 20:10:34,468 INFO] Running cmd: ip route add 91.185.207.171 via 
[2023-05-06 20:10:34,468 ERROR] /usr/lib/python3.10/subprocess.py:959: RuntimeWarning: line buffering (buffering=1) isn't supported in binary mode, the default buffer size will be used
[2023-05-06 20:10:34,468 ERROR]   self.stdout = io.open(c2pread, 'rb', bufsize)
[2023-05-06 20:10:34,468 CRITICAL] run_cmd(212): AttributeError: module 'sys' has no attribute 'maxint'
[2023-05-06 20:10:34,468 ERROR] 
[2023-05-06 20:10:34,468 INFO] Creating new SSL certificate
[2023-05-06 20:10:34,550 INFO] Using certificate: /home/matej/WSVPN/localhost.crt
[2023-05-06 20:10:34,550 INFO] Using private key: /home/matej/WSVPN/localhost.key
[2023-05-06 20:10:34,552 INFO] Client listening on tcp://127.0.0.1:8000
[2023-05-06 20:10:34,552 INFO] Will proxy requests to wss://telefoncek.si:443/ws/vpn/
```

### Set up OpenVPN client

OpenVPN WS client configuration is basically the same as normal OpenVPN configuration, except we need to define that OpenVPN will be connecting to localhost, port `8000`.

Open configuration file:
`sudo nano /etc/openvpn/Telefoncek_WS.conf`

...and change/add this setting:
 
```
remote 127.0.0.1 8000
```

### Run OpenVPN client

OpenVPN client can now be run by:
```
sudo systemctl start openvpn@Telefoncek_WS.service
```

In this example, **OpenVPN client** will connect to `localhost`, port `8000`, and from there connection will be forwarded through HTTPS encrypted websocket to `www.telefoncek.si/ws/vpn/` by **WSVPN script in client mode**.

On the server side, connection will be accepted by **Nginx** and forwarded to **WSVPN script in server mode**, listening on `localhost`, TCP port, `2000`. From there, TCP network traffic will be forwarded to **OpenVPN WS server**, listening on `localhost`, port `8001`.

### Set up OpenVPN GUI client

First we install OpenVPN support for Ubuntu's Network Manager:

`sudo apt install network-manager-openvpn network-manager-openvpn-gnome`

Then we go to the network settings and addd OpenVPN connection. Minimal required settings:
- Set the VPN connection name
- Gateway should be `127.0.0.1:8000:tcp`
- Under `Authentication` set TLS certificates: CA, user certificate and user key.
- Go to `Advanced` and under `General` set port 8000 and use TCP. Under `Security` set cypher `AES-256-CBC` and HMAC authentication `SHA-512`. Under `TLS Authentication` set authentication of server certificate, TLS-Crypt (and select `ta.key`) and minimum TLS version 1.2.

![WSVPN connection in Network Manager](https://user-images.githubusercontent.com/3339198/236640308-49df7346-d89d-4c93-9b55-55608f625ed7.png)

Now you can connect to WSVPN through GUI, **but**, you need to run WSVPN script first). 

### Autostart WSVPN on a client

We create SystemD service: `sudo systemctl --force --full edit wsvpn.service`:

```
[Unit]
Description=WSVPN
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/matej/WSVPN/wsvpn3.py -m client -l 127.0.0.1:8000 -u wss://telefoncek.si:443/ws/vpn/ -r
WorkingDirectory=/home/matej/WSVPN
StandardOutput=inherit
StandardError=inherit
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Reload all SystemD services: `sudo systemctl daemon-reload`.

Start our `wsvpn` service: `sudo systemctl start wsvpn.service`.

We can also check it's status: `sudo systemctl status wsvpn.service`, and enable it on startup: `sudo systemctl enable wsvpn.service`.

### Automatically restart WSVPN service when connect to WiFi network

If the WSVPN is active and comuter (re)connects to a WiFi network, wsvpn script nets to be restarted. In order to do this automaticlly, we first need to enable NetworkManager Dispatcher:

`sudo systemctl enable --now NetworkManager-dispatcher.service`

Now we check which is our wireless network interface: `ip a`. In our case it is `wlp3s0`.

Now, we create a script: `sudo nano /etc/NetworkManager/dispatcher.d/10-wsvpn-dispatcher.sh`

```
#/bin/sh

# This script will restart wsvpn.service if the wlp3s0 interface is up

DEVICE=${1}
STATE=${2}

if [ "$DEVICE" = "wlp3s0" ]; then
   if [ "$STATE" = "up" ]; then
      systemctl restart wsvpn.service
   fi
fi
```

Make the script executable: `sudo chmod +x /etc/NetworkManager/dispatcher.d/10-wsvpn-dispatcher.sh`.

Activate the changes to NetworkManager Dispatcher:

```
sudo systemctl daemon-reload
sudo systemctl restart NetworkManager-dispatcher.service
```

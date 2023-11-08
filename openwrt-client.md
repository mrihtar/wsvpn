# Installation of WSVPN client on OpenWrt
Target device: GL-A1300 (Slate) router.

*Please note that if you are connected to the router and the router is connected to WSVPN, clients can not connect to the VPN on the same IP where WSVPN service is running!* 

## Install dependencies
First, you need to connect to your *Slate* router (with cable or through WiFi) and then ssh to it: `ssh root@192.168.8.1`.

Then run these commands:
```
opkg update
opkg install python3-openssl
opkg install python3-psutil
opkg install python3-tornado
opkg install python3-pyopenssl
```
Now you can copy WSVPN Python script to the `/root/` directory and make it executable: `chmod +x wsvpn3.py`.

## Test the WSVPN
For confirm it is working, run the WSVPN with a command: `/usr/bin/python3 /root/wsvpn3.py -m client -l 127.0.0.1:8000 -u wss://myserver.si:443/ws/vpn/ -r`. If everything is working, you will see the output like this:
```
[2023-11-08 11:16:39,200 INFO] WSVPN VPN Websocket Proxy v1.12
[2023-11-08 11:16:39,202 INFO] Copyright (c) 2017-2023 Matej Kovacic, Gasper Zejn, Matjaz Rihtar
[2023-11-08 11:16:39,338 INFO] Running cmd: ip route
[2023-11-08 11:16:39,378 INFO] Running cmd: ip route add xx.xx.xx.xx via 192.168.40.1
[2023-11-08 11:16:39,401 INFO] Creating new SSL certificate
[2023-11-08 11:16:41,354 INFO] Using certificate: /root/localhost.crt
[2023-11-08 11:16:41,355 INFO] Using private key: /root/localhost.key
[2023-11-08 11:16:41,360 INFO] Client listening on tcp://127.0.0.1:8000
[2023-11-08 11:16:41,362 INFO] Will proxy requests to wss://myserver.si:443/ws/vpn/
```

Now you can stop the script by pressing *ctrl-c*. You will see an output like this:
```
^C[2023-11-08 11:17:09,915 INFO] Running cmd: ip route del xx.xx.xx.xx
```
## Create inid.d service
Now you can create init.d script (`/etc/init.d/wsvpn`) and copy content of [wsvpn](wsvpn) file into it.

Make the file executable: `chmod +x /etc/init.d/wsvpn`.

**Run the service**: `/etc/init.d/wsvpn start` or `service wsvpn start`. The output is like this:
```
Starting WSVPN...
WSVPN started
```
If WSVPN service is not running, you will see the notification:
```
======================================
WSVPN is not running!
======================================
```

**See the service status**: `/etc/init.d/wsvpn status` or `service wsvpn status`. Output:
```
======================================
WSVPN runnig, process ID is 21638
======================================
WSVPN output in system log:
Wed Nov  8 11:22:42 2023 user.notice wsvpn: [2023-11-08 11:22:42,526 INFO] WSVPN VPN Websocket Proxy v1.12
Wed Nov  8 11:22:42 2023 user.notice wsvpn: [2023-11-08 11:22:42,528 INFO] Copyright (c) 2017-2023 Matej Kovacic, Gasper Zejn, Matjaz Rihtar
Wed Nov  8 11:22:42 2023 user.notice wsvpn: [2023-11-08 11:22:42,532 INFO] Running cmd: ip route
Wed Nov  8 11:22:42 2023 user.notice wsvpn: [2023-11-08 11:22:42,557 INFO] Running cmd: ip route add 91.185.207.171 via 192.168.40.1
Wed Nov  8 11:22:42 2023 user.notice wsvpn: [2023-11-08 11:22:42,584 INFO] Creating new SSL certificate
Wed Nov  8 11:22:46 2023 user.notice wsvpn: [2023-11-08 11:22:46,626 INFO] Using certificate: /root/localhost.crt
Wed Nov  8 11:22:46 2023 user.notice wsvpn: [2023-11-08 11:22:46,628 INFO] Using private key: /root/localhost.key
Wed Nov  8 11:22:46 2023 user.notice wsvpn: [2023-11-08 11:22:46,635 INFO] Client listening on tcp://127.0.0.1:8000
Wed Nov  8 11:22:46 2023 user.notice wsvpn: [2023-11-08 11:22:46,637 INFO] Will proxy requests to wss://telefoncek.si:443/ws/vpn/
```

**Stop the service**: `/etc/init.d/wsvpn stop` or `service wsvpn stop`. Output:
```
Stopping WSVPN...
WSVPN stoped.
```
## Autostart WSVPN service
In a file `/etc/rc.local` put this command before the `exit 0` line:
```
/etc/init.d/wsvpn start
```

## OpenVPN connection through WSVPN
Create OpenVPN configuration on a Slate router (under `VPN` - `OpenVPN Client`). The OpenVPN client should connect to the `localhost` port `8000` via TCP, and there should be no `script` directive in the configuration, because Slate router takes care of *up* and *down* scripts by itself. So you configuration should include:

```
remote 127.0.0.1 8000
proto tcp4
```
Hint: try and test "normal" OpenVPN configuration first, and then change only `remote` directive to `127.0.0.1 8000`.

Set autostart of OpenVPN from menu `VPN` - `VPN Dashboard`.

![image](https://github.com/MatejKovacic/wsvpn/assets/3339198/7920215d-4ee1-4177-9ef5-8ce9f7983b4f)

After reboot, *Slate* router will automatically connect to WSVPN.

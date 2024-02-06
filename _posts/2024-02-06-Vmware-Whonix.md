---
title: Configuring whonix network at VMware Workstation
date: 2024-02-06 09:30:00 - 03:00
categories: [Virtualization, OPSEC]
---
```
Whonix Vware + Custom nat

In Whonix Gateway:
sudo date -s "DD MM YY HH:MM:SS" && sudo hwclock -w
> "17 OCT 2023 01:00:00" (Sempre horário do UTC)

(Configure using the NAT)
sudo ifconfig {any driver but that 10.152.xx.xx) inet 192.168.xx.xx netmask 255.255.255.0 broadcast 192.168.xx.255
sudo ip route add default via 192.168.xx.xx
> Check start and end from IP range.


sudo nano /etc/systemcheck.d/30_default.conf
"""
NO_EXIT_ON_UNSUPPORTED_VIRTUALIZER="1"

NO_EXIT_ON_IP_FORWARDING_DETECTION="1"
"""

systemcheck

sudo tor@default restart

in your VM:
(If you don't have any IP addr attributed)
sudo dhclient

(for the same driver in whonix gateway 10.152.xx.xx)

sudo ifconfig {interface} inet 10.152.152.11 netmask 255.255.192.00 broadcast 10.152.191.255
sudo ip route add default via 10.152.152.xx (THAT IP SHOWS IN Whonix)
```

---
title: Configuring whonix network at VMware Workstation
date: 2024-02-06 09:30:00 - 03:00
categories: [Virtualization, OPSEC]
---
>I don't know if this configuration is possible to make in Vmware Player (knowed by Vmware Free too). Might you can use the default network drivers and some custom NAT networks to make it, but probably it's more annoying than use the GUI.
{: .prompt-tip } 

>I did't notice any problems and you may don't need to manual configure the driver itself. So, after that.
{: .prompt-tip } 

> Also i've been used the whonix always in live mode, since the Vmware in normal boot have a huge problems about drivers and similars.
{: .prompt-tip } 

#### Whonix Vware + Custom nat

> In Whonix Gateway:
```bash
[gateway user ~]% sudo date -s "DD MM YY HH:MM:SS" && sudo hwclock -w
> "17 OCT 2023 01:00:00" (Always UTC)
```
```bash
#Configure using the NAT
[gateway user ~]% sudo ifconfig {any driver but that 10.152.xx.xx} inet 192.168.xx.xx netmask 255.255.255.0 broadcast 192.168.xx.255
[gateway user ~]% sudo ip route add default via 192.168.xx.xx
```

> Check start and end from IP range.
{: .prompt-info }

```bash
[gateway user ~]% sudo nano /etc/systemcheck.d/30_default.conf
"""
NO_EXIT_ON_UNSUPPORTED_VIRTUALIZER="1"

NO_EXIT_ON_IP_FORWARDING_DETECTION="1"
"""
```
```bash
[gateway user ~]% systemcheck

[gateway user ~]% sudo tor@default restart

[gateway user ~]% nyx
```
### Explaination:
> Since the Vmware it's a non-free software, it's considered as unsupported virtualizer, so you need to change it before run the "systemcheck". However, this proccess can be chain with other anonymous layers, like VPN's no-logs, a transparent proxy. So you can make go further about mutiple routing and trace. that's a good strategy for web-sniffers and scrappers.

#### in your VM:
```bash
(If you don't have any IP addr attributed)
Minerva at Hogwarts in ~
↪ sudo dhclient
````

> (for the same driver in whonix gateway 10.152.xx.xx)
{: .prompt-info }

```bash
Minerva at Hogwarts in ~
↪ sudo ifconfig {interface} inet 10.152.152.11 netmask 255.255.192.00 broadcast 10.152.191.255

Minerva at Hogwarts in ~
↪ sudo ip route add default via 10.152.152.xx
```

>THAT IP SHOW IN WHONIX
{: .prompt-warning }

![Desktop View](/images/a.png)
![Desktop View](/images/c.png)
![Desktop View](/images/b.png)

Well, that's a first content i'll published here.So i don't know how exactly keeping writting or extending more about the trick. Any doubts you can call me by an email or comments. 

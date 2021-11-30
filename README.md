# ipsec-zabbix-monitor

### Small parser for strongswan's ipsec statusall command

Eats (output of ipsec statusall) from stdin and gives these outputs:

with ```-a discover``` flag:

```
{
  "data": [
    {
      "{#TUNNEL}": "tunnel_1",
      "{#TUNNEL_NAME}": "tunnel-1",
      "{#LOCAL_PUBLIC_IP}": "1.1.1.1",
      "{#REMOTE_PUBLIC_IP}": "8.8.8.8",
      "{#LOCAL_INTERNAL_SUBNET}": "10.1.1.1/32",
      "{#REMOTE_INTERNAL_SUBNET}": "10.1.8.1/24",
      "{#LOCAL_PINGABLE_ENDPOINT}": "10.1.1.1",
      "{#REMOTE_PINGABLE_ENDPOINT}": "10.1.8.1"
    },
    {
      "{#TUNNEL}": "tunnel_2",
      "{#TUNNEL_NAME}": "tunnel-2",
      "{#LOCAL_PUBLIC_IP}": "1.11.1.1",
      "{#REMOTE_PUBLIC_IP}": "8.1.8.8",
      "{#LOCAL_INTERNAL_SUBNET}": "10.11.1.1/32",
      "{#REMOTE_INTERNAL_SUBNET}": "10.8.8.1/32",
      "{#LOCAL_PINGABLE_ENDPOINT}": "10.11.1.1",
      "{#REMOTE_PINGABLE_ENDPOINT}": "10.8.8.1"
    },
}
```

with ```-a monitor``` flag:

```
{
  "tunnel_1": {
    "Name": "tunnel-1",
    "BytesIn": 10204916,
    "BytesOut": 9344335,
    "Count": 1
  },
  "tunnel_2": {
    "Name": "tunnel-2",
    "BytesIn": 2270846,
    "BytesOut": 1893564,
    "Count": 0
  },
}
```

*tunnel names changes - to underscore as zabbix cant read dashes in the key of json*

Very simple script, almost no validations. Tested only with site-to-site configs. Roadwarrior is not supported!


1. Install fping
2. Build/copy binary to /etc/zabbix/bin/ipsec_zabbix_monitor
3. Allow ```zabbix``` user to run ```ipsec statusall``` with ```sudo``` by adding this line: "zabbix ALL = (ALL) NOPASSWD: /usr/sbin/ipsec statusall" to ```/etc/sudoers```
4. Add content of ```ipsec_checks.conf``` to your zabbix config
5. Import zabbix template
6. Restart zabbix agent
7. Assing template to host
8. Done =)

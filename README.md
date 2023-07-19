# flextool

Proof of concept utility to rebroadcast FlexRadio Discovery Packets to OPNSense VPN users

## about

This tool is deisgned to run on a linux machine on teh same subnet as a [FlexRadio Signature Radio](https://www.flexradio.com/comparison/) and retransmit the VITA 49 discovery packets to a group of VPN users connected to a OPNSense firewall.

## usage

This tool requires `libpcap-dev` or the correct equivalent to be installed for your operating system.

Create a `.flextool` file with the appropriate configuration for your use case.

VPN user routes can be synchronized from an OPNSENSE firewall/router using the administrative api. When each vpn connection has a common name, this tool syncs the common name and client ip address to a SQLite database for later use. A `-d` flag is used to purge the database of user records prior to inserting the latest list of VPN client ips.

The user sync can be manually executed with:

```
flextool sync -d
```

The tool can listen on a local network interface for FlexRadio discovery broadcast packets and retransmit them to all VPN ip addresses listed in the SQLite database:

```
flextool listen
```

For troubleshooting and testing, the tool also supports displaying information about the local network interfaces and can read a PCAP file and retransmit those VITA 49 packets.

```
flextool info -l
flextool info -g eth0
flextool pcap
```

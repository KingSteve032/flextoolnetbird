# flextool

Proof-of-concept utility to rebroadcast **FlexRadio Discovery Packets** to **NetBird VPN** users.

## Overview

`flextool` is designed to run on a Linux machine located on the same subnet as a [FlexRadio Signature Series Radio](https://www.flexradio.com/comparison/).

It captures **VITA 49 Discovery Packets** from the local network and retransmits them to VPN users connected through a **NetBird Management Server**. This enables FlexRadio clients running remotely (over NetBird) to detect and connect to radios as if they were on the same LAN.

## Requirements

* Go 1.22+
* `libpcap-dev` (or the equivalent package for your OS)

## Building

Clone and build:

```bash
go mod tidy
go build
```

## Configuration

Create a `.flextool` configuration file with settings appropriate for your environment.

The tool syncs NetBird VPN users and their assigned IP addresses into a local SQLite database. These IPs are then used as retransmission targets for FlexRadio discovery packets.

## Usage

### Sync NetBird VPN Users

Synchronize VPN users and their client IPs from the NetBird Management API.

```bash
flextool sync -d
```

The `-d` flag clears the database before inserting the updated list of VPN client IPs.

### Listen & Re-broadcast

Listen for FlexRadio discovery broadcasts on the LAN and retransmit them to all NetBird VPN users:

```bash
flextool listen
```

### Info & Debugging

List network interfaces:

```bash
flextool info -l
```

Show details for a specific interface:

```bash
flextool info -g eth0
```

Read a PCAP file and retransmit FlexRadio packets:

```bash
flextool pcap
```

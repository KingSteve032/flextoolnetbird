package utils

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/littleairmada/vrt"
)

type NetbirdApi struct {
	Password string
	Url      string
}

type NetInteface struct {
	Name       string
	IPAddress  net.IP
	MACAddress net.HardwareAddr
}

type ConfigOptions struct {
	Mode                  string
	PcapFile              string
	NetworkInteface       NetInteface
	Clients               []net.IP
	EnableBroadcast       bool
	EnableDebug           bool
	EnableDeleteUsers     bool
	BPFFilter             string
	NetbirdApiConnection  NetbirdApi
	BroadcastPort         int
	DiscoveryDelaySeconds int
}

type VpnRouteRow struct {
	AccessiblePeersCount int    `json:"accessible_peers_count"`
	ApprovalRequired     bool   `json:"approval_required"`
	CityName             string `json:"city_name"`
	Connected            bool   `json:"connected"`
	ConnectionIP         string `json:"connection_ip"`
	CountryCode          string `json:"country_code"`
	DNSLabel             string `json:"dns_label"`
	GeoNameID            int    `json:"geoname_id"`
	Groups               []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		PeersCount int    `json:"peers_count"`
	} `json:"groups"`
	Hostname                    string `json:"hostname"`
	ID                          string `json:"id"`
	InactivityExpirationEnabled bool   `json:"inactivity_expiration_enabled"`
	IP                          string `json:"ip"`
	KernelVersion               string `json:"kernel_version"`
	LastLogin                   string `json:"last_login"`
	LastSeen                    string `json:"last_seen"`
	LoginExpirationEnabled      bool   `json:"login_expiration_enabled"`
	LoginExpired                bool   `json:"login_expired"`
	Name                        string `json:"name"`
	OS                          string `json:"os"`
	SerialNumber                string `json:"serial_number"`
	SSHEnabled                  bool   `json:"ssh_enabled"`
	UIVersion                   string `json:"ui_version"`
	UserID                      string `json:"user_id"`
	Version                     string `json:"version"`
}

type VpnRoutes struct {
	Total    int `json:"total"`
	RowCount int `json:"rowCount"`
	Current  int `json:"current"`
	Rows     []VpnRouteRow
}

// GetNetworkInterfaceByName returns details about a single user provided interface
func GetNetworkInterfaceByName(name string) {
	netInterface, err := net.InterfaceByName(name)
	if err != nil {
		fmt.Println("Error accessing network interface: ", err)
	}
	header := "Interface Id\tInterface Name\tHardware Address\tIP Addresses\n============\t==============\t================\t============"
	var addrs_output string
	if addrs, err := netInterface.Addrs(); err == nil {
		for _, addr := range addrs {
			addrs_output = addrs_output + " " + addr.String()
		}
	}

	output := header + "\n" +
		strconv.FormatInt(int64(netInterface.Index), 10) + "\t" +
		netInterface.Name + "\t" +
		netInterface.HardwareAddr.String() + "\t" +
		addrs_output + "\n"

	fmt.Print(output)
}

// ValidateNetworkInterfaceByName returns details about a single user provided interface
func ValidateNetworkInterfaceByName(name string) (NetInteface, error) {
	netInterface, err := net.InterfaceByName(name)
	ni := NetInteface{}

	if err != nil {
		return ni, err
	}

	ni.Name = netInterface.Name
	ni.MACAddress = netInterface.HardwareAddr
	if addrs, err := netInterface.Addrs(); err == nil {
		for _, addr := range addrs {
			if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
				ni.IPAddress = ipv4Addr
				return ni, nil
			}
		}
	}

	return ni, nil
}

// PrintVrtPacket dumps VRT packet contents for debugging
func PrintVrtPacket(vrt_packet vrt.VRT) {
	fmt.Println("VRT Packet Header Type: ", vrt_packet.Header.Type)
	fmt.Println("VRT Packet Header ClassID Present?: ", vrt_packet.Header.C)
	fmt.Println("VRT Packet Header Trailer Present?: ", vrt_packet.Header.T)
	fmt.Println("VRT Packet Header TSI: ", vrt_packet.Header.TSI)
	fmt.Println("VRT Packet Header TSF: ", vrt_packet.Header.TSF)
	fmt.Println("VRT Packet Header PacketCount: ", vrt_packet.Header.PacketCount)
	fmt.Println("VRT Packet Header PacketSize: ", vrt_packet.Header.PacketSize)
	fmt.Println("VRT Packet StreamId: ", vrt_packet.StreamID)
	fmt.Println("VRT Packet ClassID OUI: ", vrt_packet.ClassID.OUI)
	fmt.Println("VRT Packet ClassID PacketClassCode: ", vrt_packet.ClassID.PacketClassCode)
	fmt.Println("VRT Packet ClassID InformationClassCode: ", vrt_packet.ClassID.InformationClassCode)
	fmt.Println("VRT Packet TimestampInt: ", vrt_packet.TimestampInt)
	fmt.Println("VRT Packet TimestampFrac: ", vrt_packet.TimestampFrac)
	fmt.Println("VRT Packet Payload length: ", len(vrt_packet.Payload))
	fmt.Println("VRT Packet Contents hexdump:")
	fmt.Println(hex.Dump(vrt_packet.Contents))
	fmt.Println("VRT Packet Payload hexdump:")
	fmt.Println(hex.Dump(vrt_packet.Payload))
}

// MaybeSendDiscoveryPacket regenerates and sends the Discovery Packet if EnableBroadcast is true
func MaybeSendDiscoveryPacket(co ConfigOptions, p vrt.VRT) {
	if !co.EnableBroadcast {
		fmt.Println("Send Discovery Packet Disabled")
		return
	}

	u, err := UsersDb()
	if err != nil {
		log.Fatal("error accessing db: ", err.Error())
	}

	// Create UDP payload from VRT packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: false}
	if err := p.SerializeTo(buf, opts); err != nil {
		fmt.Println("Unable to serialize VRT packet into byte stream: ", err)
		return
	}

	client_ips, err := u.GetUserIpAddresses()
	if err != nil {
		fmt.Println("Error retrieving vpn client ips from sqlite db: ", err)
		return
	}

	for _, clientIp := range client_ips {
		go func(ip string) {
			connectedTime, err := u.GetConnectedTime(ip)
			delay := time.Duration(co.DiscoveryDelaySeconds) * time.Second
			if err == nil && !connectedTime.IsZero() {
				elapsed := time.Since(connectedTime)
				if elapsed < delay {
					wait := delay - elapsed
					fmt.Printf("[DELAY] Waiting %v before sending discovery to %s\n", wait, ip)
					time.AfterFunc(wait, func() {
						sendDiscoveryPacketTo(ip, co, buf.Bytes())
					})
					return
				}
			}
			sendDiscoveryPacketTo(ip, co, buf.Bytes())
		}(clientIp)
	}
}

func sendDiscoveryPacketTo(clientIp string, co ConfigOptions, payload []byte) {
	fmt.Println("Sending Discovery Packet to", clientIp, "on interface", co.NetworkInteface.Name)

	serverAddr, err := net.ResolveUDPAddr("udp", clientIp+":"+strconv.Itoa(co.BroadcastPort))
	if err != nil {
		fmt.Println("error with ServerAddr:", err)
		return
	}
	localAddr, err := net.ResolveUDPAddr("udp", co.NetworkInteface.IPAddress.String()+":0")
	if err != nil {
		fmt.Println("error with LocalAddr:", err)
		return
	}
	conn, err := net.DialUDP("udp", localAddr, serverAddr)
	if err != nil {
		fmt.Println("error with Conn:", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		fmt.Println("error sending udp packet:", err)
	}
}

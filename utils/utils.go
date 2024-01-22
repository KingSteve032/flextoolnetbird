package utils

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/littleairmada/vrt"
)

type OpnsenseApi struct {
	Username string
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
	OpnsenseApiConnection OpnsenseApi
	BroadcastPort         int
}

type VpnRouteRow struct {
	VirtualAddress string `json:"virtual_address"`
	CommonName     string `json:"common_name"`
	RealAddress    string `json:"real_address"`
	LastRef        string `json:"last_ref"`
	LastRefTime    string `json:"last_ref__time_t_"`
	Type           string `json:"type"`
	ID             string `json:"id"`
	Description    string `json:"description"`
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
		//return "", err
	}
	header := "Interface Id\tInterface Name\tHardware Address\tIP Addresses\n============\t==============\t================\t============"
	var addrs_output string
	if addrs, err := netInterface.Addrs(); err == nil {
		for _, addr := range addrs {
			addrs_output = addrs_output + " " + addr.String()
		}
	}

	output := header + "\n" + strconv.FormatInt(int64(netInterface.Index), 10) + "\t" + netInterface.Name + "\t" + netInterface.HardwareAddr.String() + "\t" + addrs_output + "\n"

	fmt.Print(output)

	//return output, nil
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
	//var addrs_output string
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

func PrintVrtPacket(vrt_packet vrt.VRT) {
	fmt.Println("VRT Packet Header Type: ", vrt_packet.Header.Type)
	fmt.Println("VRT Packet Header ClassID Present?: ", vrt_packet.Header.C)
	fmt.Println("VRT Packet Header Trailer Present?: ", vrt_packet.Header.T)
	// fmt.Println("VRT Packet Header R1: ", vrt_packet.Header.R1)
	// fmt.Println("VRT Packet Header R2: ", vrt_packet.Header.R2)
	fmt.Println("VRT Packet Header TSI: ", vrt_packet.Header.TSI)
	fmt.Println("VRT Packet Header TSF: ", vrt_packet.Header.TSF)
	fmt.Println("VRT Packet Header PacketCount: ", vrt_packet.Header.PacketCount)
	fmt.Println("VRT Packet Header PacketSize: ", vrt_packet.Header.PacketSize)
	fmt.Println("VRT Packet StreamId: ", vrt_packet.StreamID)
	fmt.Println("VRT Packet ClassID OUI: ", vrt_packet.ClassID.OUI)
	//fmt.Println("VRT Packet ClassID PadBitCount: ", vrt_packet.ClassID.PadBitCount)
	fmt.Println("VRT Packet ClassID PacketClassCode: ", vrt_packet.ClassID.PacketClassCode)
	fmt.Println("VRT Packet ClassID InformationClassCode: ", vrt_packet.ClassID.InformationClassCode)
	fmt.Println("VRT Packet TimestampInt: ", vrt_packet.TimestampInt)
	fmt.Println("VRT Packet TimestampFrac: ", vrt_packet.TimestampFrac)
	//fmt.Println("VRT Packet Payload: ", vrt_packet.Payload)
	fmt.Println("VRT Packet Payload length: ", len(vrt_packet.Payload))
	// fmt.Println(len(vrt_packet.Payload) % 4)	// get modulus to see if Payload is even with byte boundary
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

	// Create udp payload using p.SerializeTo()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}
	err = p.SerializeTo(buf, opts)
	if err != nil {
		fmt.Println("Unable to serialize VRT packet into byte stream: ", err)
		return
	}

	//fmt.Println("buf.Bytes: ", hex.Dump(buf.Bytes()))

	client_ips, err := u.GetUserIpAddresses()
	if err != nil {
		fmt.Println("Error retrieving vpn client ips from sqlite db: ", err)
		return
	}

	// fmt.Println("client_ips: ", client_ips)

	// for _, clientIp := range co.Clients {
	for _, clientIp := range client_ips {
		fmt.Println("Sending to Discovery Packet to", clientIp, "on interface", co.NetworkInteface.Name)

		ServerAddr, err := net.ResolveUDPAddr("udp", clientIp+":"+strconv.FormatInt(int64(co.BroadcastPort), 10))
		if err != nil {
			fmt.Println("error with ServerAddr: ", err)
			return
		}
		LocalAddr, err := net.ResolveUDPAddr("udp", co.NetworkInteface.IPAddress.String()+":0")
		if err != nil {
			fmt.Println("DEBUG co.NetworkInteface: ", co.NetworkInteface)
			fmt.Println("error with LocalAddr: ", err)
			return
		}
		Conn, err := net.DialUDP("udp", LocalAddr, ServerAddr)
		if err != nil {
			fmt.Println("error with Conn: ", err)
			return
		}
		defer Conn.Close()

		// Send Packet
		_, err = Conn.Write(buf.Bytes())

		// fmt.Printf("Sent message %s to %s\n", msg, target)
		if err != nil {
			fmt.Println("error sending udp packet: ", err)
			return
		}
	}
}

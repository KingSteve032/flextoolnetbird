/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
*/
package cmd

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/littleairmada/flextool/utils"
	"github.com/littleairmada/vrt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func ValidateListenConfigOptions(mode string, all_flags *pflag.FlagSet) (co utils.ConfigOptions, err error) {
	// TODO: if settings is empty, return empty ConfigOptions and error
	flag_broadcast := all_flags.Lookup("broadcast").Value.String()
	flag_debug := all_flags.Lookup("debug").Value.String()
	flag_clients := all_flags.Lookup("clients").Value.String()
	flag_bpffilter := all_flags.Lookup("filter").Value.String()

	co = utils.ConfigOptions{}
	// validate MODE
	switch mode {
	case "info":
		co.Mode = "info"
	case "pcap":
		co.Mode = "pcap"
	case "listen":
		co.Mode = "listen"
	default:
		err := fmt.Errorf("the requested mode \"%s\" is not a valid mode", mode)
		return utils.ConfigOptions{}, err
	}

	// validate EnableBroadcast
	switch flag_broadcast {
	case "true":
		co.EnableBroadcast = true
	default:
		co.EnableBroadcast = false
	}

	// validate EnableDebug
	switch flag_debug {
	case "true":
		co.EnableDebug = true
	default:
		co.EnableDebug = false
	}

	// validate NetworkInteface
	flag_interface := all_flags.Lookup("interface").Value.String()
	tempNetworkInterface, err := utils.ValidateNetworkInterfaceByName(flag_interface)
	if err != nil {
		return co, err
	}
	co.NetworkInteface = tempNetworkInterface

	if flag_bpffilter != "" {
		co.BPFFilter = flag_bpffilter
	} else {
		co.BPFFilter = "udp and port 4992 and dst host 255.255.255.255"
	}

	// validate Clients
	// TODO: fix error handling
	if co.EnableBroadcast {
		var validClients []net.IP
		allClients := strings.Split(flag_clients, ",")
		for _, c := range allClients {
			cIp := net.ParseIP(string(c))
			validClients = append(validClients, cIp)
		}
		co.Clients = validClients
	}

	// Return ConfigOptions and no error
	return co, nil
}

func ListenForPackets(co utils.ConfigOptions) error {
	if handle, err := pcap.OpenLive(co.NetworkInteface.Name, 1600, false, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(co.BPFFilter); err != nil { // optional
		panic(err)
	} else {
		fmt.Printf("Listening for Discovery Packets on %s\n", co.NetworkInteface.Name)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				vrtStruct := vrt.VRT{}
				udp, _ := udpLayer.(*layers.UDP)
				if udp.Payload != nil && len(udpLayer.LayerPayload()) > 0 {
					err := vrtStruct.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback)
					if err != nil {
						// Error decoding UDP payload as VRT packet
						fmt.Println("Error decoding UDP packet as VRT: ", err)
					} else {
						if co.EnableDebug {
							utils.PrintVrtPacket(vrtStruct)
						}
						fmt.Println("FlexRadio Discovery Packet detected")
						utils.MaybeSendDiscoveryPacket(co, vrtStruct)
					}
					fmt.Println("========================")
				}
			}
			//fmt.Println("udpLayer LayerPayload: ", hex.EncodeToString(udpLayer.LayerPayload()))
		}
	}
	return nil
}

// listenCmd represents the listen command
var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listens for FlexRadio Discovery Packets on a network interface",
	Long: `
This command causes flextool to listens for FlexRadio Discovery Packets on 
a given network interface and retransmit them as UDP unicast packets to a list 
of client IP addresses. For example:

flextool listen -i eth0 -b -c 192.168.1.100
`,
	PreRun: func(cmd *cobra.Command, args []string) {
		broadcast_flag, _ := cmd.Flags().GetBool("broadcast")
		if broadcast_flag {
			cmd.MarkFlagRequired("clients")
			cmd.MarkFlagRequired("interface")
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Validate all flags
		all_flags := cmd.Flags()
		co, err := ValidateListenConfigOptions("listen", all_flags)
		if err != nil {
			fmt.Printf("INVALID CONFIGURTAION ERROR: %s\n", err)
			return
		}

		// Parse PCAP file
		ListenForPackets(co)
	},
}

func init() {
	rootCmd.AddCommand(listenCmd)

	listenCmd.Flags().BoolP("broadcast", "b", false, "Broadcast discovery packets")
	listenCmd.Flags().BoolP("debug", "d", false, "Print debug messages")
	listenCmd.Flags().StringP("clients", "c", "", "List of clients to forward Discovery Packets")
	listenCmd.Flags().StringP("interface", "i", "", "Network interface to rebroadcast packets on")
	listenCmd.Flags().String("filter", "udp and port 4992 and dst host 255.255.255.255", "Berkley packet filter rule to match packets against. Defaults to: udp and port 4992 and dst host 255.255.255.255")

	// TODO: investigate automatically populating from viper .flextool file
}

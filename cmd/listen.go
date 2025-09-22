/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
*/
package cmd

import (
	"fmt"
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kingsteve032/flextoolnetbird/utils"
	"github.com/littleairmada/vrt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func ValidateListenConfigOptions(mode string, all_flags *pflag.FlagSet) (co utils.ConfigOptions, err error) {
	// TODO: if settings is empty, return empty ConfigOptions and error
	flag_broadcast := all_flags.Lookup("broadcast").Value.String()
	flag_debug := all_flags.Lookup("debug").Value.String()
	//flag_clients := all_flags.Lookup("clients").Value.String()
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
	// if co.EnableBroadcast {
	// 	var validClients []net.IP
	// 	allClients := strings.Split(flag_clients, ",")
	// 	for _, c := range allClients {
	// 		cIp := net.ParseIP(string(c))
	// 		validClients = append(validClients, cIp)
	// 	}
	// 	co.Clients = validClients
	// }

	// Return ConfigOptions and no error
	return co, nil
}

func ViperValidateListenConfigOptions(mode string, c *viper.Viper) (co utils.ConfigOptions, err error) {
	// TODO: if settings is empty, return empty ConfigOptions and error
	flag_broadcast := c.GetBool("broadcast")
	flag_broadcastport := c.GetInt("port")
	flag_debug := c.GetBool("debug")
	flag_bpffilter := c.GetString("filter")
	flag_interface := c.GetString("interface")

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
	case true:
		co.EnableBroadcast = true
	default:
		co.EnableBroadcast = false
	}

	// validate flag_broadcastport
	if math.Signbit(float64(flag_broadcastport)) || flag_broadcastport >= 65536 {
		fmt.Println("Port number must be a valid port between 0 and 65535")
		return utils.ConfigOptions{}, err
	} else {
		co.BroadcastPort = flag_broadcastport
	}

	// validate EnableDebug
	switch flag_debug {
	case true:
		co.EnableDebug = true
	default:
		co.EnableDebug = false
	}

	// validate NetworkInteface
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

	return co, nil
}

func ListenForPackets(co utils.ConfigOptions) error {
	if handle, err := pcap.OpenLive(co.NetworkInteface.Name, 1600, false, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(co.BPFFilter); err != nil { // optional
		panic(err)
	} else {
		// fmt.Printf("Listening for Discovery Packets on %s\n", co.NetworkInteface.Name)
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
						//fmt.Println("FlexRadio Discovery Packet detected")
						utils.MaybeSendDiscoveryPacket(co, vrtStruct)
					}
					//fmt.Println("========================")
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

Listen for FlexRadio Discovery packets on 4992/udp and resend them as UDP unicast packets on 14992/udp using eth0:
flextool listen -i eth0 -b -c 192.168.1.100
`,
	Run: func(cmd *cobra.Command, args []string) {
		viperConfig := GetConfig()
		viperConfig.BindPFlag("broadcast", cmd.Flags().Lookup("broadcast"))
		viperConfig.BindPFlag("debug", cmd.Flags().Lookup("debug"))
		viperConfig.BindPFlag("interface", cmd.Flags().Lookup("interface"))
		viperConfig.BindPFlag("filter", cmd.Flags().Lookup("filter"))
		viperConfig.BindPFlag("port", cmd.Flags().Lookup("port"))

		viperConfig.AutomaticEnv()

		// Validate configuration options
		co, err := ViperValidateListenConfigOptions("listen", viperConfig)
		if err != nil {
			fmt.Printf("INVALID CONFIGURTAION ERROR: %s\n", err)
			return
		}

		// Listen for Packets
		ListenForPackets(co)
	},
}

func init() {
	rootCmd.AddCommand(listenCmd)

	// Local Flags
	listenCmd.Flags().BoolP("broadcast", "b", false, "Broadcast discovery packets")
	listenCmd.Flags().BoolP("debug", "d", false, "Print debug messages")
	listenCmd.Flags().StringP("interface", "i", "", "Network interface to rebroadcast packets on")
	listenCmd.Flags().String("filter", "udp and port 4992 and dst host 255.255.255.255", "Berkley packet filter rule to match packets against. Defaults to: udp and port 4992 and dst host 255.255.255.255")
	listenCmd.Flags().IntVarP(&broadcastPort, "port", "p", 14992, "UDP port to broadcast FlexRadio discovery packets to")
}

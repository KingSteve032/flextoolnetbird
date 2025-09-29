/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
Reconfigured for Netbird by Steven Griggs <kc4caw@w4car.org>
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
	"github.com/spf13/viper"
)

// ViperValidateListenConfigOptions validates configuration for listen mode
func ViperValidateListenConfigOptions(mode string, c *viper.Viper) (co utils.ConfigOptions, err error) {
	flag_broadcast := c.GetBool("broadcast")
	flag_broadcastport := c.GetInt("port")
	flag_debug := c.GetBool("debug")
	flag_bpffilter := c.GetString("filter")
	flag_interface := c.GetString("interface")
	delay := c.GetInt("DISCOVERY_DELAY_SECONDS")

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
		return utils.ConfigOptions{}, fmt.Errorf("the requested mode \"%s\" is not a valid mode", mode)
	}

	// validate EnableBroadcast
	co.EnableBroadcast = flag_broadcast

	// validate flag_broadcastport
	if math.Signbit(float64(flag_broadcastport)) || flag_broadcastport >= 65536 {
		return utils.ConfigOptions{}, fmt.Errorf("port number must be between 0 and 65535")
	} else {
		co.BroadcastPort = flag_broadcastport
	}

	// validate EnableDebug
	co.EnableDebug = flag_debug

	// validate NetworkInterface
	tempNetworkInterface, err := utils.ValidateNetworkInterfaceByName(flag_interface)
	if err != nil {
		return co, err
	}
	co.NetworkInteface = tempNetworkInterface

	// validate BPF filter
	if flag_bpffilter != "" {
		co.BPFFilter = flag_bpffilter
	} else {
		co.BPFFilter = "udp and port 4992 and dst host 255.255.255.255"
	}

	// add discovery delay
	co.DiscoveryDelaySeconds = delay

	if co.EnableDebug {
		fmt.Println("Discovery delay set to", co.DiscoveryDelaySeconds, "seconds")
	}

	return co, nil
}

// ListenForPackets listens for FlexRadio discovery packets and rebroadcasts them
func ListenForPackets(co utils.ConfigOptions) error {
	if handle, err := pcap.OpenLive(co.NetworkInteface.Name, 1600, false, pcap.BlockForever); err != nil {
		return err
	} else if err := handle.SetBPFFilter(co.BPFFilter); err != nil {
		return err
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				vrtStruct := vrt.VRT{}
				udp, _ := udpLayer.(*layers.UDP)
				if udp.Payload != nil && len(udpLayer.LayerPayload()) > 0 {
					err := vrtStruct.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback)
					if err != nil {
						fmt.Println("Error decoding UDP packet as VRT:", err)
					} else {
						if co.EnableDebug {
							utils.PrintVrtPacket(vrtStruct)
						}
						utils.MaybeSendDiscoveryPacket(co, vrtStruct)
					}
				}
			}
		}
	}
	return nil
}

// listenCmd represents the listen command
var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listens for FlexRadio Discovery Packets on a network interface",
	Long: `
This command listens for FlexRadio Discovery Packets on 
a given network interface and retransmits them as UDP unicast packets to VPN client IPs.

Example:
flextool listen -i eth0 -b -d
`,
	Run: func(cmd *cobra.Command, args []string) {
		viperConfig := GetConfig()
		viperConfig.BindPFlag("broadcast", cmd.Flags().Lookup("broadcast"))
		viperConfig.BindPFlag("debug", cmd.Flags().Lookup("debug"))
		viperConfig.BindPFlag("interface", cmd.Flags().Lookup("interface"))
		viperConfig.BindPFlag("filter", cmd.Flags().Lookup("filter"))
		viperConfig.BindPFlag("port", cmd.Flags().Lookup("port"))
		viperConfig.BindEnv("DISCOVERY_DELAY_SECONDS")

		viperConfig.AutomaticEnv()

		// Validate configuration options
		co, err := ViperValidateListenConfigOptions("listen", viperConfig)
		if err != nil {
			fmt.Printf("INVALID CONFIGURATION ERROR: %s\n", err)
			return
		}

		// Listen for Packets
		if err := ListenForPackets(co); err != nil {
			fmt.Println("Error while listening for packets:", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(listenCmd)

	// Local Flags
	listenCmd.Flags().BoolP("broadcast", "b", false, "Broadcast discovery packets")
	listenCmd.Flags().BoolP("debug", "d", false, "Print debug messages")
	listenCmd.Flags().StringP("interface", "i", "", "Network interface to rebroadcast packets on")
	listenCmd.Flags().String("filter", "udp and port 4992 and dst host 255.255.255.255", "Berkley packet filter rule to match packets against.")
	listenCmd.Flags().IntVarP(&broadcastPort, "port", "p", 14992, "UDP port to broadcast FlexRadio discovery packets to")
}

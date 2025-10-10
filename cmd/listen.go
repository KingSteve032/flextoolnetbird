/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
Reconfigured for Netbird by Steven Griggs <kc4caw@w4car.org>
Enhanced for separate listen/send interfaces
*/
package cmd

import (
	"fmt"
	"math"
	"strings"

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
	flag_listeniface := c.GetString("LISTEN_INTERFACE") // NEW
	flag_sendiface := c.GetString("SEND_INTERFACE")     // NEW
	flag_broadcast := c.GetBool("broadcast")
	flag_broadcastport := c.GetInt("port")
	flag_debug := c.GetBool("debug")
	flag_bpffilter := c.GetString("filter")
	delay := c.GetInt("DISCOVERY_DELAY_SECONDS")

	co = utils.ConfigOptions{}

	// validate MODE
	switch mode {
	case "listen":
		co.Mode = "listen"
	default:
		return utils.ConfigOptions{}, fmt.Errorf("invalid mode %s", mode)
	}

	// validate broadcast port
	if math.Signbit(float64(flag_broadcastport)) || flag_broadcastport >= 65536 {
		return utils.ConfigOptions{}, fmt.Errorf("port number must be between 0 and 65535")
	}
	co.BroadcastPort = flag_broadcastport

	co.EnableBroadcast = flag_broadcast
	co.EnableDebug = flag_debug
	co.DiscoveryDelaySeconds = delay

	// validate listen interface
	if flag_listeniface == "" {
		return co, fmt.Errorf("LISTEN_INTERFACE not specified")
	}
	tempListenIface, err := utils.ValidateNetworkInterfaceByName(flag_listeniface)
	if err != nil {
		return co, fmt.Errorf("error validating listen interface: %v", err)
	}
	co.ListenInterface = tempListenIface.Name

	// validate send interface
	if flag_sendiface == "" {
		return co, fmt.Errorf("SEND_INTERFACE not specified")
	}
	tempSendIface, err := utils.ValidateNetworkInterfaceByName(flag_sendiface)
	if err != nil {
		return co, fmt.Errorf("error validating send interface: %v", err)
	}
	co.SendNetworkInterface = tempSendIface

	// BPF filter
	if flag_bpffilter != "" {
		co.BPFFilter = flag_bpffilter
	} else {
		co.BPFFilter = "udp and port 4992 and dst host 255.255.255.255"
	}

	// parse ignore radios
	ignore := c.GetString("IGNORE_RADIOS")
	if ignore != "" {
		co.IgnoreRadios = strings.Split(ignore, ",")
	}

	if co.EnableDebug {
		fmt.Println("Listening on interface:", co.ListenInterface)
		fmt.Println("Sending on interface:", co.SendNetworkInterface.Name, co.SendNetworkInterface.IPAddress)
		fmt.Println("Discovery delay:", co.DiscoveryDelaySeconds, "seconds")
		fmt.Println("Ignore radios:", co.IgnoreRadios)
	}

	return co, nil
}

// ListenForPackets listens for FlexRadio discovery packets and rebroadcasts them
func ListenForPackets(co utils.ConfigOptions) error {
	if handle, err := pcap.OpenLive(co.ListenInterface, 1600, false, pcap.BlockForever); err != nil {
		return fmt.Errorf("error opening listen interface: %v", err)
	} else if err := handle.SetBPFFilter(co.BPFFilter); err != nil {
		return fmt.Errorf("error setting BPF filter: %v", err)
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
	Short: "Listens for FlexRadio Discovery Packets on one interface and sends via another",
	Long: `
Listens for FlexRadio Discovery Packets on one interface (e.g. LAN)
and retransmits them as UDP unicast packets via another (e.g. VPN).

Example:
flextool listen --listen-interface eth0 --send-interface ens18 -b -d
`,
	Run: func(cmd *cobra.Command, args []string) {
		viperConfig := GetConfig()
		viperConfig.BindPFlag("broadcast", cmd.Flags().Lookup("broadcast"))
		viperConfig.BindPFlag("debug", cmd.Flags().Lookup("debug"))
		viperConfig.BindPFlag("filter", cmd.Flags().Lookup("filter"))
		viperConfig.BindPFlag("port", cmd.Flags().Lookup("port"))
		viperConfig.BindEnv("LISTEN_INTERFACE")
		viperConfig.BindEnv("SEND_INTERFACE")
		viperConfig.BindEnv("DISCOVERY_DELAY_SECONDS")
		viperConfig.BindEnv("IGNORE_RADIOS")

		viperConfig.AutomaticEnv()

		co, err := ViperValidateListenConfigOptions("listen", viperConfig)
		if err != nil {
			fmt.Printf("INVALID CONFIGURATION ERROR: %s\n", err)
			return
		}

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
	listenCmd.Flags().String("filter", "udp and port 4992 and dst host 255.255.255.255", "Berkley packet filter rule")
	listenCmd.Flags().IntVarP(&broadcastPort, "port", "p", 14992, "UDP port to broadcast FlexRadio discovery packets to")
}

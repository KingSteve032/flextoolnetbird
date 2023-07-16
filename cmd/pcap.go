/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
*/
package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/littleairmada/flextool/utils"
	"github.com/littleairmada/vrt"
	"github.com/spf13/cobra"
)

// Set filter for VITA on 4992/udp
//var filter string = "udp and port 4992 and dst host 255.255.255.255"

// ParsePcapFile parses the given pcap file for VRT packets. Error is returned as needed.
func ParsePcapFile(co utils.ConfigOptions) error {
	fmt.Println("Parsing PCAP file...")
	if _, err := os.Stat(co.PcapFile); err == nil {
		// TODO: check if pcap_file is a pcap file

		handle, err := pcap.OpenOffline(co.PcapFile)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		err = handle.SetBPFFilter(co.BPFFilter)
		if err != nil {
			log.Fatal(err)
		}

		// Loop through packets in file
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
						if !co.EnableBroadcast {
							fmt.Println("Send Discovery Packet Disabled")
						} else {
							fmt.Println("FlexRadio Discovery Packet detected")
							utils.MaybeSendDiscoveryPacket(co, vrtStruct)
						}
					}
				}
			}
			//fmt.Println("udpLayer LayerPayload: ", hex.EncodeToString(udpLayer.LayerPayload()))
		}

	} else if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("PCAP file %s does not exist or cannot be read", co.PcapFile)
		os.Exit(0)
	} else {
		// Schrodinger: file may or may not exist. See err for details.
		fmt.Println("So a wierd thing just happened. We may have a Schrodinger file: the file may or may not exist.")
		fmt.Println("All I know is the error is:")
		fmt.Println(err)
	}

	return nil
}

// pcapCmd represents the pcap command
var pcapCmd = &cobra.Command{
	Use:   "pcap",
	Short: "Processes FlexRadio Discovery Packets from a packet capture file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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
		co, err := utils.ValidateConfigOptions("pcap", all_flags)
		if err != nil {
			fmt.Printf("INVALID CONFIGURTAION ERROR: %s\n", err)
			return
		}

		// Parse PCAP file
		ParsePcapFile(co)
	},
}

func init() {
	rootCmd.AddCommand(pcapCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pcapCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pcapCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	pcapCmd.Flags().StringP("pcapfile", "f", "", "Packet capture file (*.pcap or *.pcapng)")
	pcapCmd.Flags().BoolP("broadcast", "b", false, "Broadcast discovery packets")
	pcapCmd.Flags().BoolP("debug", "d", false, "Print debug messages")
	pcapCmd.Flags().StringP("clients", "c", "", "List of clients to forward Discovery Packets")
	pcapCmd.Flags().StringP("interface", "i", "", "Network interface to rebroadcast packets on")
	pcapCmd.Flags().String("filter", "udp and port 4992 and dst host 255.255.255.255", "Berkley packet filter rule to match packets against. Defaults to: udp and port 4992 and dst host 255.255.255.255")

	// TODO: investigate automatically populating from viper .flextool file
	// pcapfile
	// enablebroadcast (global)
	// enabledebug (global)
	// clients (global?)
}

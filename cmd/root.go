/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var config *viper.Viper
var broadcastPort int

func GetConfig() *viper.Viper {
	return config
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "flextool",
	Short: "FlexRadio Discovery Packet Rebroadcasting Tool",
	Long: `
flextool rebroadcasts FlexRadio Discovery Packets it observes 
on 4992/UDP to 14992/udp (user configurable).`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global Flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.flextool.yaml)")

	// Local Flags
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}

	c := viper.New()
	c.SetConfigType("env")
	c.SetConfigName(".flextool") // name of config file (without extension)
	if cfgFile != "" {           // enable ability to specify config file via flag
		fmt.Println(">>> cfgFile: ", cfgFile)
		c.SetConfigFile(cfgFile)
		configDir := path.Dir(cfgFile)
		if configDir != "." && configDir != dir {
			c.AddConfigPath(configDir)
		}
	}

	c.AddConfigPath(dir)
	c.AddConfigPath(".")
	c.AddConfigPath("$HOME")
	c.AutomaticEnv() // read in environment variables that match

	if err := c.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", c.ConfigFileUsed())
		config = c
	} else {
		fmt.Println(err)
	}
	c.WatchConfig()
	c.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
	})
}

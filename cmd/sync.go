/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
*/
package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/littleairmada/flextool/utils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func ViperValidateSyncConfigOptions(c *viper.Viper) (co utils.ConfigOptions, err error) {
	// TODO: if settings is empty, return empty ConfigOptions and error
	flag_delete := c.GetBool("delete")
	flag_debug := c.GetBool("debug")

	co = utils.ConfigOptions{}
	co.Mode = "sync"

	// validate EnableDeleteUsers
	switch flag_delete {
	case true:
		co.EnableDeleteUsers = true
	default:
		co.EnableDeleteUsers = false
	}

	// validate EnableDebug
	switch flag_debug {
	case true:
		co.EnableDebug = true
	default:
		co.EnableDebug = false
	}

	apiUsername := c.GetString("OPNSENSE_USERNAME")
	if apiUsername != "" {
		co.OpnsenseApiConnection.Username = apiUsername
	} else {
		err := fmt.Errorf("OPNSENSE_USERNAME is not set in the config file")
		return co, err
	}

	apiPassword := c.GetString("OPNSENSE_PASSWORD")
	if apiPassword != "" {
		co.OpnsenseApiConnection.Password = apiPassword
	} else {
		err := fmt.Errorf("OPNSENSE_PASSWORD is not set in the config file")
		return co, err
	}

	apiUrl := c.GetString("OPNSENSE_API_URL")
	if apiUrl != "" {
		co.OpnsenseApiConnection.Url = apiUrl
	} else {
		err := fmt.Errorf("OPNSENSE_API_URL is not set in the config file")
		return co, err
	}

	return co, nil
}

// GetOpnsenseVpnConnectedUsers returns a list of VPN usernames and their VPN Client IP Address
func GetOpnsenseVpnConnectedUsers(co utils.ConfigOptions) ([]utils.VpnRouteRow, error) {
	//fmt.Println("Executing GetOpnsenseVpnConnectedUsers")
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", co.OpnsenseApiConnection.Url, nil)
	if err != nil {
		// TODO: hande context deadline exceeded (timeout) error
		log.Fatal(err)
	}

	req.SetBasicAuth(co.OpnsenseApiConnection.Username, co.OpnsenseApiConnection.Password)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result utils.VpnRoutes
	json.Unmarshal([]byte(bodyText), &result)

	return result.Rows, nil
}

// syncCmd represents the info command
var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Syncs Opnsense VPN connected Users to the client list",
	Long: `Syncs Opnsense VPN connected Users to the clients table in sqlite database 'flextool.db'

Synchronize Opnsense VPN client to the sqlite database:
./flextool sync

Delete all VPN clients in the sqlite database and then synchronize Opnsense VPN clients to the database:
./flextool sync -d`,
	Run: func(cmd *cobra.Command, args []string) {
		u, err := utils.UsersDb()
		if err != nil {
			log.Fatal("error accessing db: ", err.Error())
		}

		viperConfig := GetConfig()
		viperConfig.BindPFlag("delete", cmd.Flags().Lookup("delete"))

		viperConfig.AutomaticEnv()

		co, err := ViperValidateSyncConfigOptions(viperConfig)
		if err != nil {
			fmt.Printf("INVALID CONFIGURTAION ERROR: %s\n", err)
			return
		}

		// Retrieve list of vpn connected users
		clients, err := GetOpnsenseVpnConnectedUsers(co)
		if err != nil {
			log.Fatal("error retrieving VPN users: ", err.Error())
		}
		fmt.Println(clients)

		// Delete old vpn user records from db
		if co.EnableDeleteUsers {
			u.DeleteAllUsers()
		}

		// Insert connected vpn users into db
		for _, vpnUser := range clients {
			if vpnUser.CommonName != "UNDEF" {
				u.Insert(vpnUser)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)

	syncCmd.Flags().BoolP("delete", "d", false, "deletes users from the database prior to user sync")
}

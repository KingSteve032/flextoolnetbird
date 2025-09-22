/*
Copyright © 2023 Blair Gillam <ns1h@airmada.net>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/kingsteve032/flextoolnetbird/utils"
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

	apiPassword := c.GetString("OPNSENSE_PASSWORD")
	if apiPassword != "" {
		co.NetbirdApiConnection.Password = apiPassword
	} else {
		err := fmt.Errorf("OPNSENSE_PASSWORD is not set in the config file")
		return co, err
	}

	apiUrl := c.GetString("OPNSENSE_API_URL")
	if apiUrl != "" {
		co.NetbirdApiConnection.Url = apiUrl
	} else {
		err := fmt.Errorf("OPNSENSE_API_URL is not set in the config file")
		return co, err
	}

	return co, nil
}

// / GetNetBirdConnectedUsers returns a list of VPN device names and their VPN Client IP Address
func GetNetBirdConnectedUsers(co utils.ConfigOptions) ([]utils.VpnRouteRow, error) {
	url := co.NetbirdApiConnection.Url
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Token "+co.NetbirdApiConnection.Password)

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer res.Body.Close()

	bodyText, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Print the body text (for debugging)
	fmt.Println(string(bodyText))

	// Assuming the body contains JSON that can be unmarshalled into a slice of VpnRouteRow
	var clients []utils.VpnRouteRow
	if err := json.Unmarshal(bodyText, &clients); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return clients, nil
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
		clients, err := GetNetBirdConnectedUsers(co)
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
			if vpnUser.Name != "UNDEF" {
				u.Insert(vpnUser)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)

	syncCmd.Flags().BoolP("delete", "d", false, "deletes users from the database prior to user sync")
}

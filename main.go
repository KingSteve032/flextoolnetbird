/*
Copyright © 2023 Blair Gillam
Reconfigured for Netbird by Steven Griggs <kc4caw@w4car.org>
*/
package main

import "github.com/kingsteve032/flextoolnetbird/cmd"

// FIXME: implement sanity check to see if proper libpcap libraries have been installed for the system
// func startupCheck(startup bool) {
// 	if startup {
// 		fmt.Println("TODO startupCheck")
// 	}
// }

func main() {
	//startupCheck(false)
	cmd.Execute()
}

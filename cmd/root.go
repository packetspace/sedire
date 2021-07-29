/*
Copyright © 2021 Mike Joseph <mike@mjoseph.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"strings"

	"github.com/Mike-Joseph/sedire/lib/config"
	"github.com/Mike-Joseph/sedire/lib/logging"
	"github.com/Mike-Joseph/sedire/lib/relay"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	stderrLevel string
	syslogLevel string
	addSSDP     bool
	addMDNS     bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sedire",
	Short: "The service discovery relay",
	Long: `sedire is a multicast reflector and proxy.  It is most commonly used
with service discovery protocols, including DNS-SD/mDNS and DIAL/SSDP.`,
	Run: rootCmdRun,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&cfgFile, "config", "c", "", "config file")
	pf.StringVarP(&stderrLevel, "stderr", "s", "info", "stderr logging level")
	pf.StringVarP(&syslogLevel, "syslog", "l", "disabled", "syslog logging level")
	pf.BoolVarP(&addSSDP, "ssdp", "S", false, "enable automatic handling for SSDP packets")
	pf.BoolVarP(&addMDNS, "mdns", "M", false, "enable automatic handling for mDNS packets")
	pf.StringArrayP("interface", "i", nil, "interface to use as both send and receive")
	viper.BindPFlag("send_interfaces", pf.Lookup("interface"))
	viper.BindPFlag("receive_interfaces", pf.Lookup("interface"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	logging.SetStderrLevel(stderrLevel)
	logging.SetSyslogLevel(syslogLevel)

	viper.SetDefault("proxy_mode", true)
	viper.SetDefault("response_timeout", "10s")

	if addSSDP {
		viper.SetDefault("ssdp.group", "239.255.255.250:1900")
	}
	if addMDNS {
		viper.SetDefault("mdns.group", "224.0.0.251:5353")
		viper.SetDefault("mdns.reuse_source_port", true)
	}

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigType("ini")
		viper.SetConfigFile(cfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logging.Logger.Info().Msgf("Using config file: %s", viper.ConfigFileUsed())
	}
}

func rootCmdRun(cmd *cobra.Command, args []string) {
	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			logging.Logger.Fatal().Msgf("Unable to parse argument: %s", arg)
		}
		viper.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	relays := make(map[string]*relay.Relay)
	override := viper.Sub("")
	for _, k := range viper.AllKeys() {
		parts := strings.Split(k, ".")
		if len(parts) <= 1 {
			continue
		}
		name := parts[0]
		sub := viper.Sub(name)
		if sub == nil {
			continue
		}
		c := config.Config{Child: sub, Override: override}
		g := c.GetUDP4Addr("group")
		ctx := logging.Logger.With()
		ctx = ctx.Str("relay", name)
		ctx = ctx.IPAddr("group", g.IP)
		ctx = ctx.Int("port", g.Port)
		l := ctx.Logger()
		relays[name] = &relay.Relay{
			Group:           g,
			IfiRecvList:     c.GetIfiList("receive_interfaces"),
			IfiSendList:     c.GetIfiList("send_interfaces"),
			IfiReflectList:  c.GetIfiList("reflect_interfaces"),
			ProxyMode:       c.GetBool("proxy_mode"),
			SrcPortReuse:    c.GetBool("reuse_source_port"),
			ResponseTimeout: c.GetDuration("response_timeout"),
			Logger:          logging.Instance(l),
		}
		if !c.GetBool("skip_invalid") {
			if err := relays[name].Validate(); err != nil {
				l.Fatal().Err(err).Msg("Invalid configuration for relay")
			}
		}
	}

	if viper.GetBool("run_if_empty") || len(relays) > 0 {
		for _, v := range relays {
			go v.Listen()
		}
		select {}
	}
	logging.Logger.Fatal().Msg("Nothing to do")
}

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

const (
	globalPrefix       = ""
	stderrDefaultLevel = "info"
	stdoutDefaultLevel = "disabled"
	syslogDefaultLevel = "disabled"
)

var (
	cfgFile string
	addSSDP bool
	addMDNS bool
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
	pf.StringVarP(&cfgFile, "config-file", "c", "", "config file")
	pf.StringP("stderr-level", "e", stderrDefaultLevel, "STDERR message logging level")
	pf.StringP("stdout-level", "o", stdoutDefaultLevel, "STDOUT event logging level")
	pf.StringP("syslog-level", "l", syslogDefaultLevel, "syslog message logging level")
	pf.BoolVarP(&addMDNS, "enable-mdns", "M", false, "enable automatic handling for mDNS packets")
	pf.BoolVarP(&addSSDP, "enable-ssdp", "S", false, "enable automatic handling for SSDP packets")
	pf.StringArrayP("interface", "i", nil, "interface to use as both send and receive")
	viper.BindPFlag("send_interfaces", pf.Lookup("interface"))
	viper.BindPFlag("receive_interfaces", pf.Lookup("interface"))
}

func initLogging(warn bool) {
	var err error
	c := config.Config{Override: viper.Sub(globalPrefix)}
	err = logging.Main.Stderr.SetLevel(c.GetString("stderr_level"))
	if warn && err != nil {
		defer logging.Main.Warn().Err(err).Msg("Unable to set STDERR logging level")
	}
	err = logging.Main.Stdout.SetLevel(c.GetString("stdout_level"))
	if warn && err != nil {
		defer logging.Main.Warn().Err(err).Msg("Unable to set STDOUT logging level")
	}
	err = logging.Main.Syslog.SetLevel(c.GetString("syslog_level"))
	if warn && err != nil {
		defer logging.Main.Warn().Err(err).Msg("Unable to set syslog logging level")
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	pf := rootCmd.PersistentFlags()

	viper.SetDefault("stderr_level", stderrDefaultLevel)
	viper.SetDefault("stdout_level", stdoutDefaultLevel)
	viper.SetDefault("syslog_level", syslogDefaultLevel)
	if flag := pf.Lookup("stderr-level"); flag.Changed {
		viper.SetDefault(globalPrefix+".stderr_level", flag.Value.String())
	}
	if flag := pf.Lookup("stdout-level"); flag.Changed {
		viper.SetDefault(globalPrefix+".stdout_level", flag.Value.String())
	}
	if flag := pf.Lookup("syslog-level"); flag.Changed {
		viper.SetDefault(globalPrefix+".syslog_level", flag.Value.String())
	}

	viper.SetDefault("proxy_requests", true)
	viper.SetDefault("proxy_replies", true)
	viper.SetDefault("response_timeout", "10s")

	if addMDNS {
		viper.SetDefault("mdns.group", "224.0.0.251:5353")
		viper.SetDefault("mdns.reuse_source_port_requests", true)
		viper.SetDefault("mdns.accept_unicast", true)
	}
	if addSSDP {
		viper.SetDefault("ssdp.group", "239.255.255.250:1900")
		viper.SetDefault("ssdp.proxy_replies", false)
	}

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigType("ini")
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("sedire")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		defer logging.Main.Info().Msgf("Using config file: %s", viper.ConfigFileUsed())
	}

	initLogging(false)
}

func rootCmdRun(cmd *cobra.Command, args []string) {
	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			logging.Main.Fatal().Msgf("Unable to parse argument: %s", arg)
		}
		viper.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	// Repeat initialization of logging in case the commandline parsing
	// changed the logging levels.
	initLogging(true)

	relays := make(map[string]*relay.Relay)
	override := viper.Sub(globalPrefix)
	for _, k := range viper.AllKeys() {
		parts := strings.Split(k, ".")
		if len(parts) <= 1 {
			continue
		}
		name := parts[0]
		if name == globalPrefix {
			continue
		}
		sub := viper.Sub(name)
		if sub == nil {
			continue
		}
		c := config.Config{Child: sub, Override: override}
		g := c.GetUDP4Addr("group")
		li, err := logging.NewInstance()
		ctx := li.With()
		ctx = ctx.Str("relay", name)
		ctx = ctx.Str("group", g.String())
		logger := logging.CtxLogger(ctx)
		if err != nil {
			logger.Err(err).Msg("Failed to create logging instance for relay")
		}
		if err := li.Stderr.SetLevel(c.GetString("stderr_level")); err != nil {
			defer logger.Warn().Err(err).Msg("Unable to set STDERR logging level for relay")
		}
		if err := li.Stdout.SetLevel(c.GetString("stdout_level")); err != nil {
			defer logger.Warn().Err(err).Msg("Unable to set STDOUT logging level for relay")
		}
		if err := li.Syslog.SetLevel(c.GetString("syslog_level")); err != nil {
			defer logger.Warn().Err(err).Msg("Unable to set syslog logging level for relay")
		}
		relays[name] = &relay.Relay{
			Group:               g,
			IfiRecvList:         c.GetIfiList("receive_interfaces"),
			IfiSendList:         c.GetIfiList("send_interfaces"),
			IfiReflectList:      c.GetIfiList("reflect_interfaces"),
			AcceptUnicast:       c.GetBool("accept_unicast"),
			ProxyRequests:       c.GetBool("proxy_requests"),
			ProxyReplies:        c.GetBool("proxy_replies"),
			RequestSrcPortReuse: c.GetBool("reuse_source_port_requests"),
			ReplySrcPortReuse:   c.GetBool("reuse_source_port_replies"),
			ResponseTimeout:     c.GetDuration("response_timeout"),
			Logger:              logger,
		}
		if !c.GetBool("skip_invalid") {
			relays[name].Validate(true)
		}
		relays[name].Initialize()
	}

	if viper.GetBool("run_if_empty") || len(relays) > 0 {
		for _, v := range relays {
			go v.Listen()
		}
		select {}
	}
	logging.Main.Fatal().Msg("Nothing to do")
}

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

package config

import (
	"net"
	"time"

	"github.com/mike-joseph/sedire/lib/logging"

	"github.com/spf13/viper"
)

type Config struct {
	Viper *viper.Viper
	Order []string
}

func New(viper *viper.Viper, prefixes ...string) *Config {
	return &Config{
		Viper: viper,
		Order: prefixes,
	}
}

func (c *Config) getViper() *viper.Viper {
	if c.Viper != nil {
		return c.Viper
	}
	return viper.GetViper()
}

func (c *Config) getKey(key string) string {
	v := c.getViper()
	k := key
	if c.Order != nil {
		for _, pfx := range c.Order {
			k = pfx + "." + key
			if v.IsSet(k) {
				break
			}
		}
	}
	return k
}

func (c *Config) GetBool(key string) bool {
	return c.getViper().GetBool(c.getKey(key))
}

func (c *Config) GetString(key string) string {
	return c.getViper().GetString(c.getKey(key))
}

func (c *Config) GetStringSlice(key string) []string {
	return c.getViper().GetStringSlice(c.getKey(key))
}

func (c *Config) GetDuration(key string) time.Duration {
	return c.getViper().GetDuration(c.getKey(key))
}

func (c *Config) GetUDP4Addr(key string) *net.UDPAddr {
	str := c.GetString(key)
	addr, err := net.ResolveUDPAddr("udp4", str)
	if err != nil {
		logging.Main.Err(err).Msgf("Unable to parse group address: %s", str)
	}
	return addr
}

func (c *Config) GetIfiList(key string) []*net.Interface {
	strList := c.GetStringSlice(key)
	ifiList := make([]*net.Interface, 0, len(strList))
	for _, name := range strList {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			logging.Main.Err(err).Msgf("Interface not found: %s", name)
			continue
		}
		ifiList = append(ifiList, ifi)
	}
	return ifiList
}

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

	"github.com/Mike-Joseph/sedire/lib/logging"

	"github.com/spf13/viper"
)

type Config struct {
	Parent   *viper.Viper
	Child    *viper.Viper
	Override *viper.Viper
}

func (c Config) getViperInstance(key string) *viper.Viper {
	if c.Override != nil && c.Override.IsSet(key) {
		return c.Override
	}
	if c.Child != nil && c.Child.IsSet(key) {
		return c.Child
	}
	if c.Parent != nil {
		return c.Parent
	}
	return viper.GetViper()
}

func (c Config) GetBool(key string) bool {
	return c.getViperInstance(key).GetBool(key)
}

func (c Config) GetString(key string) string {
	return c.getViperInstance(key).GetString(key)
}

func (c Config) GetStringSlice(key string) []string {
	return c.getViperInstance(key).GetStringSlice(key)
}

func (c Config) GetDuration(key string) time.Duration {
	return c.getViperInstance(key).GetDuration(key)
}

func (c Config) GetUDP4Addr(key string) *net.UDPAddr {
	str := c.GetString(key)
	addr, err := net.ResolveUDPAddr("udp4", str)
	if err != nil {
		logging.Logger.Err(err).Msgf("Unable to parse group address: %s", str)
	}
	return addr
}

func (c Config) GetIfiList(key string) []*net.Interface {
	strList := c.GetStringSlice(key)
	ifiList := make([]*net.Interface, 0, len(strList))
	for _, name := range strList {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			logging.Logger.Err(err).Msgf("Interface not found: %s", name)
			continue
		}
		ifiList = append(ifiList, ifi)
	}
	return ifiList
}

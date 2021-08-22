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

package relay

import (
	"net"
	"sync"
)

var (
	interfaceIndexCache sync.Map
)

func interfaceByIndex(index int) (*net.Interface, error) {
	if ifi, ok := interfaceIndexCache.Load(index); ok {
		return ifi.(*net.Interface), nil
	}
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		interfaceIndexCache.Store(index, ifi)
	}
	return ifi, err
}

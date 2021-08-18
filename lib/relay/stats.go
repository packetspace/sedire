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
	"reflect"
	"sync/atomic"
)

type RelayStats struct {
	ForwardedRequests     uint64 `json:"forwarded_requests"`
	ForwardedReplies      uint64 `json:"forwarded_replies"`
	ProxiedRequests       uint64 `json:"proxied_requests"`
	ProxiedReplies        uint64 `json:"proxied_replies"`
	SrcPortReusedRequests uint64 `json:"src_port_reused_requests"`
	SrcPortReusedReplies  uint64 `json:"src_port_reused_replies"`
	PacketsReceived       uint64 `json:"packets_received"`
	PacketsSent           uint64 `json:"packets_sent"`
	BytesReceived         uint64 `json:"bytes_received"`
	BytesSent             uint64 `json:"bytes_sent"`
}

func (r *Relay) GetStats() (rs RelayStats) {
	rs.ForwardedRequests = atomic.LoadUint64(&r.stats.ForwardedRequests)
	rs.ForwardedReplies = atomic.LoadUint64(&r.stats.ForwardedReplies)
	rs.ProxiedRequests = atomic.LoadUint64(&r.stats.ProxiedRequests)
	rs.ProxiedReplies = atomic.LoadUint64(&r.stats.ProxiedReplies)
	rs.SrcPortReusedRequests = atomic.LoadUint64(&r.stats.SrcPortReusedRequests)
	rs.SrcPortReusedReplies = atomic.LoadUint64(&r.stats.SrcPortReusedReplies)
	rs.PacketsReceived = atomic.LoadUint64(&r.stats.PacketsReceived)
	rs.PacketsSent = atomic.LoadUint64(&r.stats.PacketsSent)
	rs.BytesReceived = atomic.LoadUint64(&r.stats.BytesReceived)
	rs.BytesSent = atomic.LoadUint64(&r.stats.BytesSent)
	return
}

func (r *Relay) LogStats() {
	rs := r.GetStats()
	e := r.Logger.Info()
	rst := reflect.TypeOf(rs)
	rsv := reflect.ValueOf(rs)
	for i := 0; i < rst.NumField(); i++ {
		f := rst.Field(i)
		k := f.Name
		if j, ok := f.Tag.Lookup("json"); ok {
			k = j
		}
		v := rsv.Field(i).Interface()
		e.Interface(k, v)
	}
	e.Msg("Relay statistics")
}

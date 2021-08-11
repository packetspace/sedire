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
	"time"

	"github.com/Mike-Joseph/sedire/lib/logging"

	mapset "github.com/deckarep/golang-set"
)

const IPv4mcast = "224.0.0.0"

type Relay struct {
	Group               *net.UDPAddr
	IfiRecvList         []*net.Interface
	IfiSendList         []*net.Interface
	IfiReflectList      []*net.Interface
	AcceptUnicast       bool
	ProxyRequests       bool
	ProxyReplies        bool
	RequestSrcPortReuse bool
	ReplySrcPortReuse   bool
	ResponseTimeout     time.Duration
	Logger              logging.LoggerInstance

	mcastListener packetConn
}

func (r *Relay) relayRequest(pc packetConn, p packet, reflect bool, ifIndices mapset.Set, logger logging.LoggerInstance) {
	recvIfIndex := p.Ifi.Index
	p.Src = &net.UDPAddr{Port: pc.LocalAddr().(*net.UDPAddr).Port}
	p.Dst = r.Group
	if reflect {
		if r.ProxyRequests {
			p.writeTo(pc, logger, "Reflected proxied request packet back to received interface")
		} else {
			p.sendRaw(logger, "Reflected native request packet back to received interface")
		}
		if ifIndices != nil {
			ifIndices.Add(p.Ifi.Index)
		}
	}
	for _, ifi := range r.IfiSendList {
		if ifi.Index != recvIfIndex {
			p.Ifi = ifi
			if r.ProxyRequests {
				p.writeTo(pc, logger, "Relayed request packet")
			} else {
				p.sendRaw(logger, "Forwarded native request packet")
			}
			if ifIndices != nil {
				ifIndices.Add(ifi.Index)
			}
		}
	}
}

func (r *Relay) proxyRequest(req packet, reflect bool, deadline time.Time, logger logging.LoggerInstance) {
	logger.Trace().Time("timeout", deadline).Msg("Starting proxy")
	proxyConn, err := listenUDP4(&net.UDPAddr{})
	if err != nil {
		logger.Err(err).Msg("Failed to initialize proxy socket")
		return
	}
	defer proxyConn.Close()
	xmitIfIndices := mapset.NewThreadUnsafeSet()
	r.relayRequest(proxyConn, req, reflect, xmitIfIndices, logger)
	if err := proxyConn.SetReadDeadline(deadline); err != nil {
		logger.Err(err).Msg("Failed to set timeout on proxy socket")
		return
	}
	for {
		p, err := readFrom(proxyConn)
		if err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr != nil && netErr.Timeout() {
				logger.Trace().Msg("Proxy expired")
			} else {
				logger.Err(err).Msg("Unexpected read error on proxy socket")
			}
			break
		}
		ctx := logger.With()
		ctx = ctx.Str("reply_receive_interface", p.Ifi.Name)
		ctx = ctx.Str("reply_src_address", p.Src.String())
		ctx = ctx.Str("reply_dst_address", p.Dst.String())
		ctx = ctx.Int("reply_packet_size", len(p.Msg))
		l := ctx.Logger()
		if xmitIfIndices.Contains(p.Ifi.Index) {
			l.Trace().Msg("Processing proxy reply packet")
			pc := proxyConn
			if r.ReplySrcPortReuse && p.Src.Port == r.Group.Port {
				pc = r.mcastListener
			}
			p.Ifi = nil
			p.Src = &net.UDPAddr{Port: pc.LocalAddr().(*net.UDPAddr).Port}
			p.Dst = req.Src
			if r.ProxyReplies {
				p.writeTo(pc, logging.Instance(l), "Relayed reply packet to client")
			} else {
				p.sendRaw(logging.Instance(l), "Forwarded native reply packet to client")
			}
		} else {
			l.Trace().Msg("Discarding proxy reply packet received on unexpected interface")
		}
	}
}

func (r *Relay) Validate(fatal bool) bool {
	event := r.Logger.Error()
	if fatal {
		event = r.Logger.Fatal()
	} else {
		w := r.Logger.Warn()
		if r.ProxyReplies && !r.ProxyRequests {
			w.Msg("proxy_replies ignored without proxy_requests")
		}
		if r.RequestSrcPortReuse && !r.ProxyRequests {
			w.Msg("src_port_reuse_requests ignored without proxy_requests")
		}
		if r.ReplySrcPortReuse && !r.ProxyReplies {
			w.Msg("src_port_reuse_replies ignored without proxy_replies")
		}
		if r.RequestSrcPortReuse && !r.AcceptUnicast {
			w.Msg("accept_unicast strongly recommended with src_port_reuse_requests")
		}
	}
	e := func(msg string) bool {
		event.Str("error", msg).Msg("Failed to start relay instance")
		return false
	}
	if !r.Group.IP.IsMulticast() {
		return e("group must have a valid multicast address")
	}
	if r.Group.Port <= 0 || r.Group.Port >= 65535 {
		return e("group must have a valid UDP port")
	}
	if len(r.IfiRecvList) < 1 {
		return e("at least one receive interface must be defined")
	}
	if len(r.IfiSendList)+len(r.IfiReflectList) < 1 {
		return e("at least one send or reflect interface must be defined")
	}
	return true
}

func (r *Relay) Initialize() {
	if !r.ProxyRequests || !r.ProxyReplies {
		StartRaw()
	}
}

func (r *Relay) Listen() {
	r.Logger.Trace().Msg("Starting multicast listener")
	if !r.Validate(false) {
		return
	}
	pc, err := listenUDP4(&net.UDPAddr{
		IP:   net.ParseIP(IPv4mcast),
		Port: r.Group.Port,
	})
	if err != nil {
		r.Logger.Err(err).Msg("Failed to initialize multicast socket")
		return
	}
	defer pc.Close()
	recvIfIndices := mapset.NewThreadUnsafeSet()
	for _, ifi := range r.IfiRecvList {
		ctx := r.Logger.With()
		ctx = ctx.Str("interface", ifi.Name)
		ctx = ctx.Int("ifIndex", ifi.Index)
		l := ctx.Logger()
		if err := pc.JoinGroup(ifi, r.Group); err != nil {
			l.Err(err).Msg("Failed to join multicast group on listener socket")
			continue
		}
		l.Debug().Msg("Joined multicast group on listener socket")
		recvIfIndices.Add(ifi.Index)
	}
	reflectIfIndices := mapset.NewThreadUnsafeSet()
	for _, ifi := range r.IfiReflectList {
		reflectIfIndices.Add(ifi.Index)
	}
	r.mcastListener = pc
	r.Logger.Info().Msg("Started multicast listener")
	for {
		p, err := readFrom(r.mcastListener)
		if err != nil {
			r.Logger.Err(err).Msg("Error reading from listener socket")
			break
		}
		ctx := r.Logger.With()
		ctx = ctx.Str("request_receive_interface", p.Ifi.Name)
		ctx = ctx.Str("request_src", p.Src.String())
		ctx = ctx.Str("request_dst", p.Dst.String())
		ctx = ctx.Int("request_packet_size", len(p.Msg))
		l := ctx.Logger()
		if (p.Dst.IP.Equal(r.Group.IP) || (r.AcceptUnicast && p.Dst.IP.IsGlobalUnicast())) && recvIfIndices.Contains(p.Ifi.Index) {
			reflect := reflectIfIndices.Contains(p.Ifi.Index)
			l.Trace().Msg("Processing packet destined to this relay")
			logger := logging.Instance(l)
			if !r.ProxyRequests || (r.RequestSrcPortReuse && p.Src.Port == r.Group.Port) {
				r.relayRequest(r.mcastListener, p, reflect, nil, logger)
			} else {
				deadline := time.Now().Add(r.ResponseTimeout)
				go r.proxyRequest(p, reflect, deadline, logger)
			}
		} else {
			l.Trace().Msg("Discarding packet not destined to this relay")
		}
	}
	r.Logger.Warn().Msg("This relay instance is terminating")
}

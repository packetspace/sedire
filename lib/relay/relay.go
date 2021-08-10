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
	"errors"
	"net"
	"time"

	"github.com/Mike-Joseph/sedire/lib/logging"

	mapset "github.com/deckarep/golang-set"
	"golang.org/x/net/ipv4"
)

var IPv4mcast = net.IPNet{
	IP:   net.IPv4(224, 0, 0, 0),
	Mask: net.CIDRMask(4, 32),
}

type Relay struct {
	Group               *net.UDPAddr
	IfiRecvList         []*net.Interface
	IfiSendList         []*net.Interface
	IfiReflectList      []*net.Interface
	ProxyMode           bool
	RequestSrcPortReuse bool
	ReplySrcPortReuse   bool
	ResponseTimeout     time.Duration
	Logger              logging.LoggerInstance
	mcastListener       *ipv4.PacketConn
}

type packet struct {
	Msg []byte
	Ifi *net.Interface
	Src *net.UDPAddr
	Dst *net.UDPAddr
}

func readFrom(pc *ipv4.PacketConn) (*packet, error) {
	buf := make([]byte, 65536)
	n, cm, src, err := pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	ifi, err := net.InterfaceByIndex(cm.IfIndex)
	if err != nil {
		return nil, err
	}
	p := &packet{
		Msg: buf[:n],
		Ifi: ifi,
		Src: src.(*net.UDPAddr),
		Dst: &net.UDPAddr{
			IP:   cm.Dst,
			Port: pc.LocalAddr().(*net.UDPAddr).Port,
		},
	}
	return p, nil
}

func (r *Relay) relayPacket(pc *ipv4.PacketConn, p *packet, reflect bool, ifIndices mapset.Set, logger logging.LoggerInstance) {
	for _, ifi := range r.IfiSendList {
		if ifi.Index != p.Ifi.Index {
			if err := pc.SetMulticastInterface(ifi); err != nil {
				r.Logger.Err(err).Msg("Failed to set multicast interface")
				continue
			}
			if _, err := pc.WriteTo(p.Msg, nil, r.Group); err != nil {
				r.Logger.Err(err).Msg("Failed to transmit message to multicast group")
				continue
			}
			ctx := logger.With()
			ctx = ctx.Str("xmit_interface", ifi.Name)
			ctx = ctx.Str("xmit_src", pc.LocalAddr().String())
			ctx = ctx.Str("xmit_dst", r.Group.String())
			l := ctx.Logger()
			l.Debug().Msg("Relayed request packet")
			if ifIndices != nil {
				ifIndices.Add(ifi.Index)
			}
		}
	}
	if err := pc.SetMulticastInterface(p.Ifi); err != nil {
		r.Logger.Err(err).Msg("Failed to set multicast interface")
		return
	}
	if reflect {
		if _, err := pc.WriteTo(p.Msg, nil, r.Group); err != nil {
			r.Logger.Err(err).Msg("Failed to reflect message back to multicast group")
			return
		}
		ctx := logger.With()
		ctx = ctx.Str("xmit_interface", p.Ifi.Name)
		ctx = ctx.Str("xmit_src", pc.LocalAddr().String())
		ctx = ctx.Str("xmit_dst", r.Group.String())
		l := ctx.Logger()
		l.Debug().Msg("Reflected request packet back to received interface")
		if ifIndices != nil {
			ifIndices.Add(p.Ifi.Index)
		}
	}
}

func (r *Relay) proxyRequest(req *packet, reflect bool, deadline time.Time, logger logging.LoggerInstance) {
	logger.Trace().Time("timeout", deadline).Msg("Starting proxy")
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		logger.Err(err).Msg("Could not bind proxy socket")
		return
	}
	defer conn.Close()
	proxyConn := ipv4.NewPacketConn(conn)
	if err := proxyConn.SetMulticastLoopback(false); err != nil {
		logger.Err(err).Msg("Could not disable multicast loopback on proxy socket")
		return
	}
	xmitIfIndices := mapset.NewThreadUnsafeSet()
	r.relayPacket(proxyConn, req, reflect, xmitIfIndices, logger)
	if err := proxyConn.SetControlMessage(ipv4.FlagDst, true); err != nil {
		logger.Err(err).Msg("Could not enable Dst flag on proxy socket")
		return
	}
	if err := proxyConn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		logger.Err(err).Msg("Could not enable Interface flag on proxy socket")
		return
	}
	if err := proxyConn.SetReadDeadline(deadline); err != nil {
		logger.Err(err).Msg("Could not set deadline on proxy socket")
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
			if _, err := pc.WriteTo(p.Msg, nil, req.Src); err != nil {
				l.Err(err).Msg("Failed to forward reply to client")
				continue
			}
			ctx = l.With()
			ctx = ctx.Str("xmit_src", pc.LocalAddr().String())
			ctx = ctx.Str("xmit_dst", req.Src.String())
			l := ctx.Logger()
			l.Debug().Msg("Relayed reply packet to client")
		} else {
			l.Trace().Msg("Discarding proxy reply packet received on unexpected interface")
		}
	}
}

func (r *Relay) Validate() error {
	if !r.ProxyMode {
		return errors.New("proxy mode must be enabled in current version")
	}
	if !IPv4mcast.Contains(r.Group.IP) {
		return errors.New("group must have a valid multicast address")
	}
	if r.Group.Port <= 0 || r.Group.Port >= 65535 {
		return errors.New("group must have a valid UDP port")
	}
	if len(r.IfiRecvList) < 1 {
		return errors.New("at least one receive interface must be defined")
	}
	if len(r.IfiSendList)+len(r.IfiReflectList) < 1 {
		return errors.New("at least one send or reflect interface must be defined")
	}
	return nil
}

func (r *Relay) Listen() {
	r.Logger.Trace().Msg("Starting multicast listener")
	if err := r.Validate(); err != nil {
		r.Logger.Err(err).Msg("Could not start multicast listener")
		return
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: IPv4mcast.IP, Port: r.Group.Port})
	if err != nil {
		r.Logger.Err(err).Msg("Could not bind multicast listener socket")
		return
	}
	defer conn.Close()
	r.mcastListener = ipv4.NewPacketConn(conn)
	if err := r.mcastListener.SetMulticastLoopback(false); err != nil {
		r.Logger.Err(err).Msg("Could not disable multicast loopback on listener socket")
		return
	}
	recvIfIndices := mapset.NewThreadUnsafeSet()
	for _, ifi := range r.IfiRecvList {
		ctx := r.Logger.With()
		ctx = ctx.Str("interface", ifi.Name)
		ctx = ctx.Int("ifIndex", ifi.Index)
		l := ctx.Logger()
		if err := r.mcastListener.JoinGroup(ifi, r.Group); err != nil {
			l.Err(err).Msg("Could not join multicast group on listener socket")
			continue
		}
		l.Debug().Msg("Joined multicast group on listener socket")
		recvIfIndices.Add(ifi.Index)
	}
	reflectIfIndices := mapset.NewThreadUnsafeSet()
	for _, ifi := range r.IfiReflectList {
		reflectIfIndices.Add(ifi.Index)
	}
	if err := r.mcastListener.SetControlMessage(ipv4.FlagDst, true); err != nil {
		r.Logger.Err(err).Msg("Could not enable Dst flag on listener socket")
		return
	}
	if err := r.mcastListener.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		r.Logger.Err(err).Msg("Could not enable Interface flag on listener socket")
		return
	}
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
		if p.Dst.IP.Equal(r.Group.IP) && recvIfIndices.Contains(p.Ifi.Index) {
			reflect := reflectIfIndices.Contains(p.Ifi.Index)
			l.Trace().Msg("Processing packet destined to this relay")
			logger := logging.Instance(l)
			if r.RequestSrcPortReuse && p.Src.Port == r.Group.Port {
				r.relayPacket(r.mcastListener, p, reflect, nil, logger)
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

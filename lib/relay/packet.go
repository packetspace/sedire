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
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/Mike-Joseph/sedire/lib/logging"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

type packet struct {
	Msg []byte
	Ifi *net.Interface
	Src *net.UDPAddr
	Dst *net.UDPAddr
}

type packetConn struct {
	*ipv4.PacketConn
}

var rawConn struct {
	rc *ipv4.RawConn
	mu sync.Mutex
}

func listenUDP4(addr *net.UDPAddr) (pc packetConn, err error) {
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return
	}
	pc = packetConn{ipv4.NewPacketConn(conn)}
	if err = pc.SetMulticastLoopback(false); err != nil {
		pc.Close()
		return
	}
	if err = pc.SetControlMessage(ipv4.FlagDst, true); err != nil {
		pc.Close()
		return
	}
	if err = pc.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		pc.Close()
		return
	}
	return
}

func readFrom(pc packetConn) (p packet, err error) {
	buf := make([]byte, 65536)
	n, cm, src, err := pc.ReadFrom(buf)
	if err != nil {
		return
	}
	ifi, err := interfaceByIndex(cm.IfIndex)
	if err != nil {
		return
	}
	p.Msg = buf[:n]
	p.Ifi = ifi
	p.Src = src.(*net.UDPAddr)
	p.Dst = &net.UDPAddr{
		IP:   cm.Dst,
		Port: pc.LocalAddr().(*net.UDPAddr).Port,
	}
	return
}

func (p *packet) writeTo(pc packetConn, logger logging.Logger, success string) {
	var cm *ipv4.ControlMessage
	ctx := logger.With()
	if p.Src != nil && p.Src.IP != nil {
		if cm == nil {
			cm = &ipv4.ControlMessage{}
		}
		cm.Src = p.Src.IP
		addr := *p.Src
		addr.Port = pc.LocalAddr().(*net.UDPAddr).Port
		ctx = ctx.Str("xmit_src", addr.String())
	} else {
		ctx = ctx.Str("xmit_src", pc.LocalAddr().String())
	}
	if p.Dst != nil && p.Dst.IP != nil {
		ctx = ctx.Str("xmit_dst", p.Dst.String())
	} else {
		logger.Panic().Msg("relay.writeTo() called without p.Dst")
	}
	if p.Ifi != nil {
		if p.Dst.IP.IsMulticast() {
			if err := pc.SetMulticastInterface(p.Ifi); err != nil {
				logger.Err(err).Msg("Failed to set multicast interface")
				return
			}
		} else {
			if cm == nil {
				cm = &ipv4.ControlMessage{}
			}
			cm.IfIndex = p.Ifi.Index
		}
		ctx = ctx.Str("xmit_interface", p.Ifi.Name)
	}
	if p.Msg == nil {
		logger.Panic().Msg("relay.writeTo() called without p.Msg")
	}
	l := logging.CtxLogger(ctx)
	if _, err := pc.WriteTo(p.Msg, nil, p.Dst); err != nil {
		l.Err(err).Msg("Failed to send packet")
		return
	}
	l.Debug().Msg(success)
}

func (p *packet) sendRaw(logger logging.Logger, success string) {
	if p.Src == nil {
		logger.Panic().Msg("relay.sendRaw() called without p.Src")
	}
	if p.Src.IP == nil {
		logger.Panic().Msg("relay.sendRaw() called without p.Src.IP")
	}
	if p.Dst == nil {
		logger.Panic().Msg("relay.sendRaw() called without p.Dst")
	}
	if p.Dst.IP == nil {
		logger.Panic().Msg("relay.sendRaw() called without p.Dst.IP")
	}
	if p.Msg == nil {
		logger.Panic().Msg("relay.writeTo() called without p.Msg")
	}
	var cm *ipv4.ControlMessage
	ctx := logger.With()
	if p.Ifi != nil {
		ctx = ctx.Str("xmit_interface", p.Ifi.Name)
	}
	ctx = ctx.Str("xmit_src", p.Src.String())
	ctx = ctx.Str("xmit_dst", p.Dst.String())
	l := logging.CtxLogger(ctx)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(p.Src.Port),
		DstPort: layers.UDPPort(p.Dst.Port),
	}
	ip := &layers.IPv4{
		Version:  ipv4.Version,
		TTL:      1,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    p.Src.IP,
		DstIP:    p.Dst.IP,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		l.Err(err).Msg("Failed to set UDP/IP layer in raw packet")
		return
	}
	if err := gopacket.SerializeLayers(buf, opts, udp, gopacket.Payload(p.Msg)); err != nil {
		l.Err(err).Msg("Failed to serialize raw packet payload")
		return
	}
	payload := buf.Bytes()
	h := &ipv4.Header{
		Version:  int(ip.Version),
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(payload),
		TTL:      int(ip.TTL),
		Protocol: int(ip.Protocol),
		Src:      ip.SrcIP,
		Dst:      ip.DstIP,
	}
	rawConn.mu.Lock()
	defer rawConn.mu.Unlock()
	if p.Ifi != nil {
		if p.Dst.IP.IsMulticast() {
			if err := rawConn.rc.SetMulticastInterface(p.Ifi); err != nil {
				logger.Err(err).Msg("Failed to set multicast interface")
				return
			}
		} else {
			if cm == nil {
				cm = &ipv4.ControlMessage{}
			}
			cm.IfIndex = p.Ifi.Index
		}
	}
	if err := rawConn.rc.WriteTo(h, payload, cm); err != nil {
		l.Err(err).Msg("Failed to send raw packet")
		return
	}
	l.Debug().Msg(success)
}

func StartRaw() {
	rawConn.mu.Lock()
	defer rawConn.mu.Unlock()
	if rawConn.rc == nil {
		protocol := fmt.Sprintf("ip4:%d", syscall.IPPROTO_RAW)
		conn, err := net.ListenIP(protocol, &net.IPAddr{})
		if err != nil {
			logging.Main.Fatal().Err(err).Msg("Failed to bind raw socket")
		}
		rawConn.rc, err = ipv4.NewRawConn(conn)
		if err != nil {
			logging.Main.Fatal().Err(err).Msg("Failed to create raw connection")
		}
		logging.Main.Trace().Msg("Created raw socket for sending")
	}
}

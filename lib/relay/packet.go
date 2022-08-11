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

	"github.com/mike-joseph/sedire/lib/logging"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

type packet struct {
	Msg []byte
	Ifi *net.Interface
	Src *net.UDPAddr
	Dst *net.UDPAddr
	TTL uint8
}

type packetConn struct {
	*ipv4.PacketConn
	mu sync.Mutex
}

type rawConn struct {
	*ipv4.RawConn
	mu sync.Mutex
}

var mainRC = rawConn{}

func listenUDP4(addr *net.UDPAddr) (pc *packetConn, err error) {
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return
	}
	pc = &packetConn{PacketConn: ipv4.NewPacketConn(conn)}
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
	if err = pc.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		pc.Close()
		return
	}
	return
}

func readFrom(pc *packetConn) (p packet, err error) {
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
	p.TTL = uint8(cm.TTL)
	return
}

func (p *packet) validateWrite(srcRequired, ttlRequired bool, logger logging.Logger) {
	if p == nil {
		logger.Panic().Msg("Packet write method called with nil packet")
	}
	if srcRequired {
		if p.Src == nil {
			logger.Panic().Msg("Packet write method called without p.Src")
		} else {
			if p.Src.IP == nil {
				logger.Panic().Msg("Packet write method called without p.Src.IP")
			}
			if p.Src.Port <= 0 || p.Src.Port > 65535 {
				logger.Panic().Msg("Packet write method called with invalid p.Src.Port")
			}
		}
	} else if p.Src != nil && (p.Src.Port < 0 || p.Src.Port > 65535) {
		// p.Src.Port == 0 is permitted here since a default will be used
		logger.Panic().Msg("Packet write method called with invalid p.Src.Port")
	}
	if p.Dst == nil {
		logger.Panic().Msg("Packet write method called without p.Dst")
	}
	if p.Dst.IP == nil {
		logger.Panic().Msg("Packet write method called without p.Dst.IP")
	}
	if p.Dst.Port <= 0 || p.Dst.Port > 65535 {
		logger.Panic().Msg("Packet write method called with invalid p.Dst.Port")
	}
	if p.Dst.IP.IsMulticast() && p.Ifi == nil {
		logger.Panic().Msg("Packet write method called with multicast destination and no interface")
	}
	if ttlRequired && p.TTL == 0 {
		logger.Panic().Msg("Packet write method called without p.Msg")
	}
	if p.Msg == nil {
		logger.Panic().Msg("Packet write method called without p.Msg")
	}
}

func (p *packet) writeTo(pc *packetConn, logger logging.Logger, success string) {
	p.validateWrite(false, false, logger)
	var cm *ipv4.ControlMessage
	addr := *pc.LocalAddr().(*net.UDPAddr)
	if p.Src != nil {
		if p.Src.IP != nil {
			if cm == nil {
				cm = &ipv4.ControlMessage{}
			}
			cm.Src = p.Src.IP
			addr.IP = p.Src.IP
		}
		if p.Src.Port > 0 && p.Src.Port != addr.Port {
			logger.Panic().Msg("writeTo() called with p.Src.Port different from sending socket port")
		}
	}
	ctx := logger.With()
	if p.Ifi != nil {
		ctx = ctx.Str("xmit_interface", p.Ifi.Name)
	}
	ctx = ctx.Stringer("xmit_src", &addr)
	ctx = ctx.Stringer("xmit_dst", p.Dst)
	l := logging.CtxLogger(ctx)
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if p.Ifi != nil {
		if p.Dst.IP.IsMulticast() {
			if err := pc.SetMulticastInterface(p.Ifi); err != nil {
				l.Err(err).Msg("Failed to set multicast interface")
				return
			}
			l.Trace().Msg("Set multicast interface on socket")
		} else {
			if cm == nil {
				cm = &ipv4.ControlMessage{}
			}
			cm.IfIndex = p.Ifi.Index
		}
	}
	if p.TTL > 0 {
		var dstType string
		var getTTLfunc func() (int, error)
		var setTTLfunc func(int) error
		if p.Dst.IP.IsMulticast() {
			dstType = "multicast"
			getTTLfunc = pc.MulticastTTL
			setTTLfunc = pc.SetMulticastTTL
		} else {
			dstType = "unicast"
			getTTLfunc = pc.TTL
			setTTLfunc = pc.SetTTL
		}
		ttl, err := getTTLfunc()
		if err != nil {
			l.Err(err).Msgf("Failed to obtain current %s TTL", dstType)
			return
		}
		if err := setTTLfunc(int(p.TTL)); err != nil {
			l.Err(err).Msgf("Failed to set %s TTL", dstType)
			return
		}
		l.Trace().Uint8("ttl", p.TTL).Msgf("Set %s TTL on socket", dstType)
		defer func() {
			if err := setTTLfunc(ttl); err != nil {
				l.Err(err).Msgf("Failed to restore %s TTL", dstType)
				return
			}
			l.Trace().Int("ttl", ttl).Msgf("Restored %s TTL on socket", dstType)
		}()
	}
	if _, err := pc.WriteTo(p.Msg, cm, p.Dst); err != nil {
		l.Err(err).Msg("Failed to send packet")
		return
	}
	l.Debug().Msg(success)
}

func (p *packet) writeRaw(logger logging.Logger, success string) {
	p.validateWrite(true, true, logger)
	var cm *ipv4.ControlMessage
	ctx := logger.With()
	if p.Ifi != nil {
		ctx = ctx.Str("xmit_interface", p.Ifi.Name)
	}
	ctx = ctx.Stringer("xmit_src", p.Src)
	ctx = ctx.Stringer("xmit_dst", p.Dst)
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
		TTL:      p.TTL,
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
	mainRC.mu.Lock()
	defer mainRC.mu.Unlock()
	if p.Ifi != nil {
		if p.Dst.IP.IsMulticast() {
			if err := mainRC.SetMulticastInterface(p.Ifi); err != nil {
				l.Err(err).Msg("Failed to set multicast interface")
				return
			}
		} else {
			if cm == nil {
				cm = &ipv4.ControlMessage{}
			}
			cm.IfIndex = p.Ifi.Index
		}
	}
	if err := mainRC.WriteTo(h, payload, cm); err != nil {
		l.Err(err).Msg("Failed to send raw packet")
		return
	}
	l.Debug().Msg(success)
}

func StartRaw() {
	mainRC.mu.Lock()
	defer mainRC.mu.Unlock()
	if mainRC.RawConn == nil {
		protocol := fmt.Sprintf("ip4:%d", syscall.IPPROTO_RAW)
		conn, err := net.ListenIP(protocol, &net.IPAddr{})
		if err != nil {
			logging.Main.Fatal().Err(err).Msg("Failed to bind raw socket")
		}
		mainRC.RawConn, err = ipv4.NewRawConn(conn)
		if err != nil {
			logging.Main.Fatal().Err(err).Msg("Failed to create raw connection")
		}
		logging.Main.Trace().Msg("Created raw socket for sending")
	}
}

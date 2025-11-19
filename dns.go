package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func processUDPPackets(ctx context.Context, reader *ringbuf.Reader) {
	seenDNSPackets := map[statEntry]struct{}{}
	resetSeenPacketsTick := time.NewTicker(time.Minute)
	defer resetSeenPacketsTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-resetSeenPacketsTick.C:
			// Reset the seenDNSPacketIDs map every once in a while so it doesn't grow unbounded,
			// as well the unlikely case a random ID gets re-used. There is a small chance we reset
			// this in between processing packets that would result in a duplicate entry, but that's fine.
			seenDNSPackets = map[statEntry]struct{}{}
		default:
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}

				log.Printf("Error reading UDP Packet: %v", err)
				continue
			}

			udpPktDetails, packet, err := parseUDPPacketRecord(record)
			if err != nil {
				log.Printf("Error handling UDP Packet: %v", err)
				continue
			}

			layer := packet.Layer(layers.LayerTypeDNS)
			if layer == nil {
				log.Printf("Skipping udp packet: does not contain a dns layer")
				continue
			}

			dnsLayer, ok := layer.(*layers.DNS)
			if !ok {
				log.Printf("Skipping udp packet: couldn't convert to dns layer")
				continue
			}

			if len(dnsLayer.Questions) == 0 {
				log.Printf("Skipping dns packet: no questions")
				continue
			}

			if shouldSkipDNSEntry(dnsLayer.Questions[0]) {
				continue
			}

			entry := statEntry{
				SrcPort:       udpPktDetails.SrcPort,
				SrcIP:         bytesToAddr(udpPktDetails.Srcip.In6U.U6Addr8),
				DstPort:       udpPktDetails.DstPort,
				DstIP:         bytesToAddr(udpPktDetails.Dstip.In6U.U6Addr8),
				Proto:         "UDP",
				Pid:           udpPktDetails.Pid,
				Comm:          comm2String(udpPktDetails.Comm[:]),
				DNSQueryName:  string(dnsLayer.Questions[0].Name),
				LikelyService: "dns",
			}

			if getKubeClient() != nil {
				entry.SourcePod = lookupPodForIP(entry.SrcIP)
				entry.DstPod = lookupPodForIP(entry.DstIP)
			}

			// Currently we see the same DNS packet make it's journey from the originating process,
			// to the local dns resolver, and on it's way out of the VM's network. This results in
			// quite a few duplicate events being printed to stdout. So check if this would cause
			// a duplicate output and skip printing it if so.
			if _, ok := seenDNSPackets[entry]; ok {
				log.Printf("Skipping DNS packet we've already seen")
				continue
			} else {
				seenDNSPackets[entry] = struct{}{}
			}

			entry.Timestamp = time.Now().UTC()
			fmt.Print(outputJSON([]statEntry{entry}))
		}
	}
}

var specialUseDomains = []string{
	".alt.",
	".6tisch.arpa.",
	".eap.arpa.",
	".eap-noob.arpa.",
	".home.arpa.",
	".10.in-addr.arpa.",
	".254.169.in-addr.arpa.",
	".16.172.in-addr.arpa.",
	".17.172.in-addr.arpa.",
	".18.172.in-addr.arpa.",
	".19.172.in-addr.arpa.",
	".20.172.in-addr.arpa.",
	".21.172.in-addr.arpa.",
	".22.172.in-addr.arpa.",
	".23.172.in-addr.arpa.",
	".24.172.in-addr.arpa.",
	".25.172.in-addr.arpa.",
	".26.172.in-addr.arpa.",
	".27.172.in-addr.arpa.",
	".28.172.in-addr.arpa.",
	".29.172.in-addr.arpa.",
	".30.172.in-addr.arpa.",
	".31.172.in-addr.arpa.",
	".170.0.0.192.in-addr.arpa.",
	".171.0.0.192.in-addr.arpa.",
	".168.192.in-addr.arpa.",
	".8.e.f.ip6.arpa.",
	".9.e.f.ip6.arpa.",
	".a.e.f.ip6.arpa.",
	".b.e.f.ip6.arpa.",
	".ipv4only.arpa.",
	".resolver.arpa.",
	".service.arpa.",
	".example.",
	".example.com.",
	".example.net.",
	".example.org.",
	".invalid.",
	".local.",
	".localhost.",
	".onion.",
	".test.",
}

func shouldSkipDNSEntry(question layers.DNSQuestion) bool {
	if question.Type == layers.DNSTypeHINFO {
		return true
	}

	// Skip DNS queries for the current hostname
	queryName := strings.TrimSuffix(string(question.Name), ".")
	if hostname, err := os.Hostname(); err == nil {
		if strings.EqualFold(queryName, hostname) {
			return true
		}
	}

	if externalOnly != nil && *externalOnly {
		normalizedDomain := strings.ToLower(string(question.Name))
		if !strings.HasSuffix(normalizedDomain, ".") {
			normalizedDomain += "."
		}

		for _, specialDomain := range specialUseDomains {
			if strings.HasSuffix(normalizedDomain, specialDomain) {
				return true
			}
		}
	}

	return false
}

func parseUDPPacketRecord(rec ringbuf.Record) (counterUdpPkt, gopacket.Packet, error) {
	udpPkt := counterUdpPkt{}
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &udpPkt); err != nil {
		return udpPkt, nil, fmt.Errorf("reading record: %w", err)
	}

	pktBytes := [4096]byte(udpPkt.Pkt)
	parsedPacket := gopacket.NewPacket(pktBytes[:], layers.LayerTypeDNS, gopacket.DecodeOptions{NoCopy: true})
	return udpPkt, parsedPacket, nil
}

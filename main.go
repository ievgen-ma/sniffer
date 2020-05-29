package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"strconv"
	"time"
)

var (
	snaplen int32 = 65535
	promisc       = false
	err     error
	timeout time.Duration = -1 * time.Second
	handle  *pcap.Handle
	// Listen to packets on port 443 (https), find offset of tcp payload and check if it starts with the TLS magic number and version SSLVv3 or TLSv1.x.
	filter string = "tcp and port 443 and tcp[(((tcp[12:1] & 0xf0) >> 2)):1] = 0x16 and ((tcp[(((tcp[12:1] & 0xf0) >> 2)+5):1] = 0x01) or (tcp[(((tcp[12:1] & 0xf0) >> 2)+5):1] = 0x02))"
)

func main() {
	var device string
	flag.StringVar(&device, "device", "eth0", "device name")

	flag.Parse()

	handle, err = pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ipPacket := ipLayer.(*layers.IPv4)

		IP_SRC := ipPacket.SrcIP.String()
		IP_DST := ipPacket.DstIP.String()

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcpPacket := tcpLayer.(*layers.TCP)

		TCP_SRC := tcpPacket.SrcPort.String()
		TCP_DST := tcpPacket.DstPort.String()
		COUNT_TCP_OPTIONS := strconv.Itoa(len(tcpPacket.Options))

		fmt.Fprintln(os.Stdout, fmt.Sprintf("%s,%s,%s,%s,%s", IP_SRC, TCP_SRC, IP_DST, TCP_DST, COUNT_TCP_OPTIONS))
	}
}

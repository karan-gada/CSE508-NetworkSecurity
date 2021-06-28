package main
import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/pborman/getopt"
	"encoding/hex"
	"log"
	"strings"
)

var(
	handle *pcap.Handle
	err error
	string_input *string
)

func dataHandler(packet gopacket.Packet){

	//This part picks out data from the Ethernet Layer packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		src_mac := ethernetPacket.SrcMAC
		dest_mac := ethernetPacket.DstMAC
		ether_type := ethernetPacket.EthernetType
		
		//Reading the Application Layer packet if exists
		pay_load := ""
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil{
			pay_load = hex.Dump(applicationLayer.Payload())
		}

		//Support for ARP protocol
		if arpPacket := packet.Layer(layers.LayerTypeARP); arpPacket != nil{
			fmt.Printf("%s %s -> %s type 0x%x len %d\n%s", packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.32536"),
			src_mac,dest_mac, int64(ether_type), packet.Metadata().Length, pay_load)
		}

		//Support for IPv4
		if ipv4Packet := packet.Layer(layers.LayerTypeIPv4); ipv4Packet != nil{
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ipPacket, _ := ipLayer.(*layers.IPv4)
			src_ip := ipPacket.SrcIP
			dst_ip := ipPacket.DstIP
			ip_proto := ipPacket.Protocol.String()
			
			//Checking the protocol mentioned in IPv4  
			if (ip_proto != "TCP" && ip_proto != "UDP" && ip_proto != "ICMPv4") {
				ip_proto = "Other"
			}

			//This part picks out data from the TCP Layer packet
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			tcp_seq_str := ""
			//Finding the flags set in the TCP packet
			if tcpLayer != nil{
				tcpPacket := tcpLayer.(*layers.TCP)
				if  tcpPacket.FIN{
					tcp_seq_str = tcp_seq_str + "FIN "
				}
				if  tcpPacket.SYN{
					tcp_seq_str = tcp_seq_str + "SYN "
				}
				if  tcpPacket.RST{
					tcp_seq_str = tcp_seq_str + "RST "
				}
				if  tcpPacket.PSH{
					tcp_seq_str = tcp_seq_str + "PSH "
				}
				if tcpPacket.ACK{
					tcp_seq_str = tcp_seq_str + "ACK "
				}
				if tcpPacket.URG{
					tcp_seq_str = tcp_seq_str + "URG "
				}
				if tcpPacket.ECE{
					tcp_seq_str = tcp_seq_str + "ECE "
				}
				if tcpPacket.CWR{
					tcp_seq_str = tcp_seq_str + "CWR "
				}
				if tcpPacket.NS{
					tcp_seq_str = tcp_seq_str + "NS "
				}
			}
			
			//Checking if '-s' flag is set from command-line check for the string 
			//mentioned along with the flag in the content of the packet
			if getopt.IsSet('s'){
				if(!strings.Contains(pay_load, *string_input)){
					return
				}
			}
			fmt.Printf("%s %s -> %s type 0x%x len %d\n%s -> %s %s %s\n%s", packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.32536"),
			src_mac,dest_mac, int64(ether_type), packet.Metadata().Length,src_ip, dst_ip, ip_proto, tcp_seq_str, pay_load)
		}
	}
	
}

func main(){
	//This part is to read the values from the command-line flags
	inter_face := getopt.String('i',"eth0","The interface to connect")
	read_file := getopt.String('r', "", "Read pcap file mentioned")
	string_input = getopt.String('s', "", "The string to match in the message payload")
	getopt.Lookup('s').SetOptional()
	getopt.Parse()

	//Checking if '-r' flag is set. If set use the string along with
	//the flag as the input to open a .pcap file
	//If '-r' is not set use the value from '-i' flag to read from Live Server
	//If '-i' is not provided use the default connection 'eth0' to read packets
	if getopt.IsSet('r'){
		handle, err = pcap.OpenOffline(*read_file);
		if err != nil {log.Fatal(err)}
		defer handle.Close()
	} else {
		handle, err = pcap.OpenLive(*inter_face, 1024, true, pcap.BlockForever)
    	if err != nil {log.Fatal(err) }
    	defer handle.Close()
	}

	//This part checks if there are any non-parameteric values in command-line 
	//and uses them as expression for the BPF filter
	if len(getopt.Args()) > 0{
		filter_input_array := getopt.Args()
		filter_input := strings.Join(filter_input_array, " ")
		handle.SetBPFFilter(filter_input)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
			dataHandler(packet)	
	}
}

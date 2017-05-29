package icmpservice

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"syscall"
	"time"
)

func noresponse() {
	time.Sleep(2 * time.Second)
	fmt.Println("No response from the host")
	os.Exit(1)
}

func initSocket() (fd int) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil || fd < 0 {
		fmt.Println("ERROR, creating raw socket")
		os.Exit(1)
	}
	return
}

// ReceiveAllICMPPackets is function for recv ALL ICMP packets that arrive on network interface
func ReceiveAllICMPPackets() {
	fd := initSocket()
	f := os.NewFile(uintptr(fd), fmt.Sprintf("sockfd%d", fd))
	for {
		buf := make([]byte, 1024)
		rb, err := f.Read(buf)
		if err != nil {
			fmt.Println("ERROR, can't read info from socket")
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(buf[:rb]))
	}
}

// sendICMPPacket is function for sending ICMP packet(ECHO_REQEUST) on remote/localhost machine
func sendICMPPacketTo(fd int, destAddr syscall.SockaddrInet4, icmppacket []byte) {
	err := syscall.Sendto(fd, icmppacket, 0, &destAddr)
	if err != nil {
		fmt.Println("ERROR, can't send ICMP packet")
		os.Exit(1)
	}
}

func receiveICMPPacketFrom(fd int, destAddr syscall.SockaddrInet4) bool {
	icmppacket := make([]byte, 28)
	socketF := os.NewFile(uintptr(fd), fmt.Sprintf("sock%v", fd))
	defer socketF.Close()
	for {
		rb, err := socketF.Read(icmppacket)
		if rb >= 28 && err == nil && icmppacket[20] == 0x0 { // if it's ICMP ECHO reply packet
			if reflect.DeepEqual(icmppacket[12:16], destAddr.Addr[:]) {
				return true
			}
		}
	}
}

func receiveMyExceededICMPPackets(fd int, origpacket []byte) {
	icmppacket := make([]byte, 56)
	socketF := os.NewFile(uintptr(fd), fmt.Sprintf("sock%v", fd))
	defer socketF.Close()
	for {
		rb, err := socketF.Read(icmppacket)
		if rb >= 28 && err == nil && icmppacket[20] == 0x0B { // if it's ICMP TTL exceeded
			if reflect.DeepEqual(icmppacket[48:], origpacket[:]) {
				fmt.Println(fmt.Sprintf("%v.%v.%v.%v", icmppacket[12], icmppacket[13], icmppacket[14], icmppacket[15]))
			}
		}
	}
}

// IsAlive function for cheking host in the network (ON/OFF)
func IsAlive(ipbytes [4]byte) {
	destAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: ipbytes,
	}
	fd := initSocket()
	icmppacket := createSimpleEchoRequest()
	sendICMPPacketTo(fd, destAddr, icmppacket)
	go noresponse()
	if receiveICMPPacketFrom(fd, destAddr) {
		fmt.Println("Host is alive!")
	}
}

// TraceRouteWithTTL function for trace routing
func TraceRouteWithTTL(ipbytes [4]byte) {
	fmt.Println("TRACEROUTE START (THIS ->", ipbytes, ")\n")
	destAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: ipbytes,
	}
	fd := initSocket()
	icmppacket := createSimpleEchoRequest()
	socketF := os.NewFile(uintptr(fd), fmt.Sprintf("sock%v", fd))
	defer socketF.Close()
	for i := 1; ; i++ {
		fmt.Print(" ", i, ".\t")
		syscall.SetsockoptByte(fd, syscall.IPPROTO_IP, syscall.IP_TTL, uint8(i))
		curtime := time.Now()
		sendICMPPacketTo(fd, destAddr, icmppacket)
		rcvicmppacket := make([]byte, 56)
		rb, err := socketF.Read(rcvicmppacket)
		recvtime := fmt.Sprintf("%.2f ms", float64(time.Since(curtime))/1e6)
		if rb >= 28 && err == nil {
			switch rcvicmppacket[20] {
			case 0x0: // if it's ICMP ECHO reply
				{
					if reflect.DeepEqual(rcvicmppacket[12:16], ipbytes[:]) {
						fmt.Println(fmt.Sprintf("%v.%v.%v.%v\t(ECHO reply)\t\t%s\n\nTRACEROUTE END", rcvicmppacket[12],
							rcvicmppacket[13], rcvicmppacket[14], rcvicmppacket[15], recvtime))
						os.Exit(0)
					}
				}
			case 0x0B: // if it's ICMP TTL exceeded
				{
					if reflect.DeepEqual(rcvicmppacket[48:], icmppacket[:]) {
						fmt.Println(fmt.Sprintf("%v.%v.%v.%v\t(TTL exceeded)\t\t%s", rcvicmppacket[12], rcvicmppacket[13],
							rcvicmppacket[14], rcvicmppacket[15], recvtime))
					}
				}
			default:
				{
					if reflect.DeepEqual(rcvicmppacket[48:], icmppacket[:]) {
						fmt.Println(fmt.Sprintf("%v.%v.%v.%v\t(Other: %vt/%vc)\t\t%s", rcvicmppacket[12], rcvicmppacket[13],
							rcvicmppacket[14], rcvicmppacket[15], rcvicmppacket[20], rcvicmppacket[21], recvtime))
					}
				}
			}
		}
	}
}

// Function for creating simple echo icmp request
func createSimpleEchoRequest() []byte {
	request := make([]byte, 8)
	request[0] = 0x8
	request[4] = uint8(rand.Int())
	calcsum := CalculateСsumPacket(request)
	request[2] = uint8((calcsum >> 8) & 0xFF)
	request[3] = uint8(calcsum & 0xFF)
	return request
}

// CalculateСsumPacket is function for calc. csum for any packets(IP/ICMP/TCP/UDP etc)
func CalculateСsumPacket(buf []byte) uint16 {
	sum := uint32(0)
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

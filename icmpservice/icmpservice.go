package icmpservice

import (
	"encoding/hex"
	"fmt"
	"os"
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
func sendICMPPacketTo(fd int, destAddr syscall.SockaddrInet4) {
	// creating simple echo request
	icmppacket := make([]byte, 8)
	icmppacket[0] = 0x8
	calcsum := CalculateСsumPacket(icmppacket)
	icmppacket[2] = uint8((calcsum >> 8) & 0xFF)
	icmppacket[3] = uint8(calcsum & 0xFF)
	err := syscall.Sendto(fd, icmppacket, 0, &destAddr)
	if err != nil {
		fmt.Println("ERROR, can't send ICMP packet")
		os.Exit(1)
	}
}

func receiveICMPPacketFrom(fd int, destAddr syscall.SockaddrInet4) {
	icmppacket := make([]byte, 28)
	isAlive := true
	socketF := os.NewFile(uintptr(fd), fmt.Sprintf("sock%v", fd))
	defer socketF.Close()

	go noresponse()
	for {
		rb, err := socketF.Read(icmppacket)
		if rb >= 28 && err == nil && icmppacket[21] == 0x0 { // if it's ICMP ECHO reply packet
			for i, val := range icmppacket[12:15] {
				if destAddr.Addr[i] != val {
					isAlive = false
					break
				}
			}
			if isAlive {
				fmt.Println("Host is alive!")
				break
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
	sendICMPPacketTo(fd, destAddr)
	receiveICMPPacketFrom(fd, destAddr)
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

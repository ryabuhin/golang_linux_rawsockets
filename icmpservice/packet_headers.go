package icmpservice

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"syscall"
)

type ip_head struct {
	ip_verhlen, ip_tosecn         uint8
	ip_len, ip_id, ip_flagsoffset uint16
	ip_ttl, ip_proto              uint8
	ip_csum                       uint16
	ip_sourceaddr, ip_destaddr    uint32
}

// method for installation source addr in ip layer packet
func (iph *ip_head) setSourceAddr(ip_sourceaddr []byte) {
	iph.ip_sourceaddr = binary.BigEndian.Uint32(ip_sourceaddr[:])
}

//  method for installation source addr in ip layer packet
func (iph *ip_head) setDestAddr(ip_destaddr []byte) {
	iph.ip_destaddr = binary.BigEndian.Uint32(ip_destaddr[:])
}

type icmp_head struct {
	icmp_type, icmp_code uint8
	icmp_csum            uint16
}

type icmp_packet struct {
	icmphead      []byte
	icmphead_info []byte
}

func ConvertPacketToBytes(packet interface{}) []byte {
	var pbytes bytes.Buffer
	binary.Write(&pbytes, binary.BigEndian, packet)
	return pbytes.Bytes()
}

// Function for creating simple icmp request | struct
func CreateSimpleStructICMPHeader(icmp_type, icmp_code byte) icmp_head {
	icmphead := icmp_head{
		icmp_type: icmp_type,
		icmp_code: icmp_code,
	}
	return icmphead
}

// Function for creating simple icmp request | return bytes
func CreateSimpleBytesICMPHeader(icmp_type, icmp_code byte) []byte {
	var icmphbytes bytes.Buffer
	icmpheadstr := CreateSimpleStructICMPHeader(icmp_type, icmp_code)
	icmpheadstr.icmp_type = icmp_type
	icmpheadstr.icmp_code = icmp_code
	binary.Write(&icmphbytes, binary.BigEndian, icmpheadstr)
	return icmphbytes.Bytes()
}

// Function for creating simple ip header whithout csum/source/dest | struct
func CreateSimpleStructIPHeader() ip_head {
	iphead := ip_head{
		ip_verhlen:     0x45,
		ip_tosecn:      0x0,
		ip_len:         0x14,
		ip_id:          uint16(rand.Int()),
		ip_flagsoffset: 0x0,
		ip_ttl:         0x40,
		ip_proto:       syscall.IPPROTO_ICMP,
	}
	return iphead
}

// Function for creating simple ip header whithout csum/source/dest | return bytes
func CreateSimpleBytesIPHeader() []byte {
	var iphbytes bytes.Buffer
	binary.Write(&iphbytes, binary.BigEndian, CreateSimpleStructIPHeader())
	return iphbytes.Bytes()
}

// Function for calculating and installation csum for packet
func CalculatePacketCsum(packet []byte, pcsum *[]byte) {
	calcsum := calculateСsumPacket(packet)
	(*pcsum)[0] = uint8((calcsum >> 8) & 0xFF)
	(*pcsum)[1] = uint8(calcsum & 0xFF)
}

// calculateСsumPacket is function for calc. csum for any packets(IP/ICMP/TCP/UDP etc)
func calculateСsumPacket(buf []byte) uint16 {
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

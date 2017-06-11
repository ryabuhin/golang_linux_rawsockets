package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"ryabuhin/socketraw/icmpservice"
	"strconv"
	"strings"
)

// [--isalive ip] [--traceroute ip] [--recvall]
func main() {
	switch os.Args[1] {
	case "--isalive":
		{
			icmpservice.IsAlive(parseIP(os.Args[2]))
		}
	case "--traceroute":
		{
			icmpservice.TraceRouteWithTTL(parseIP(os.Args[2]))
			os.Exit(1)
		}
	case "--recvall":
		{
			os.Exit(1)
		}
	case "--redirhost":
		{
			icmpservice.IcmpRedirectHost(parseIP(os.Args[2]), parseIP(os.Args[3]), parseIP(os.Args[4]),
				parseIP(os.Args[5]))
		}
	}
	os.Exit(0)
}

func parseIP(argip string) (ipbytes [4]byte) {
	addrs, err := net.LookupHost(argip)
	if err == nil {
		re := regexp.MustCompile("([0-9]{0,3}\\.){3}[0-9]{0,3}")
		ip := re.FindAllString(addrs[0], -1)
		if len(ip) == 1 {
			ipsplit := strings.Split(ip[0], ".")
			tmp, _ := strconv.Atoi(ipsplit[0])
			ipbytes[0] = uint8(tmp)
			tmp, _ = strconv.Atoi(ipsplit[1])
			ipbytes[1] = uint8(tmp)
			tmp, _ = strconv.Atoi(ipsplit[2])
			ipbytes[2] = uint8(tmp)
			tmp, _ = strconv.Atoi(ipsplit[3])
			ipbytes[3] = uint8(tmp)
		}
	} else {
		fmt.Println("ERROR, unknown host")
		os.Exit(1)
	}
	return
}

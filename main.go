package main

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	cidr        string
	hostsRange  []string
	scanTimeout int
	scanThreads int
	firstPort   int
	lastPort    int
	knPorts     KnownPorts
)

const UNKNOWN = "<unknown>"

type KnownPorts struct {
	Services []struct {
		Description string `yaml:"description"`
		Port        int    `yaml:"port"`
	} `yaml:"services"`
}

type tmpHostScanResult struct {
	host       string
	enablePort []int
}

type portScanner struct {
	host    string
	timeout time.Duration
	threads int
}

type defaultPorts struct {
	Services []struct {
		Description string `yaml:"description"`
		Port        int    `yaml:"port"`
	} `yaml:"services"`
}

func init() {
	knPorts = portsFromConfig()
}

func main() {
	flag.StringVar(&cidr, "target", "127.0.0.1", "/ Single IP address or CIDR or hostname")
	flag.IntVar(&scanTimeout, "timeout", 1, "/ Time in seconds")
	flag.IntVar(&scanThreads, "threads", 5, "/ Parallel connections")
	flag.IntVar(&firstPort, "firstPort", 20, "/ First port of scanning")
	flag.IntVar(&lastPort, "lastPort", 65536, "/ Last port of scanning")
	flag.Parse()

	fmt.Printf("target: %s\n", cidr)

	var err error
	switch {
	case strings.Contains(cidr, "/"):
		hostsRange, err = getHosts(cidr)
		if err != nil {
			panic(err.Error())
		}
		fmt.Printf("You entered CIDR Address %s. The Range of CIDR looks: %s\n", cidr, hostsRange)
	case isLetter(cidr):
		ipaddr, err := net.ResolveIPAddr("ip4", cidr)
		if err != nil {
			panic(err.Error())
		}
		hostsRange = append(hostsRange, ipaddr.String())
		fmt.Printf("You entered HostName: %s. The Target IP looks: %s\n", cidr, hostsRange)
	default:
		hostsRange = append(hostsRange, cidr)
		fmt.Printf("You entered IP: %s. THe Target IP looks: %s\n", cidr, hostsRange)
	}

	for _, host := range hostsRange {
		result := scanHost(host, scanTimeout, scanThreads, firstPort, lastPort)
		if len(result.enablePort) > 0 {
			processingResult(result.host, result.enablePort)
		} else {
			fmt.Printf("Scan has not found opend ports on host %s from port %d to %d, nothing to add into result. \n\n", host, firstPort, lastPort)
		}
	}

}

func getHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
		return nil, err
	}

	var ips []string
	for ip = ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func scanHost(host string, timeout, threads, firstPort, lastPort int) tmpHostScanResult {
	scanner := NewPortScanner(host, time.Duration(timeout)*time.Second, threads)
	fmt.Printf("Scanning Ports: %d ~ %d on host %s....\n\n", firstPort, lastPort, host)

	openPortList := scanner.GetOpenPortList(firstPort, lastPort)

	var tmp tmpHostScanResult
	tmp.host = host
	for i := 0; i < len(openPortList); i++ {
		port := openPortList[i]
		tmp.enablePort = append(tmp.enablePort, port)
	}

	return tmp
}

func NewPortScanner(host string, timeout time.Duration, threads int) *portScanner {
	return &portScanner{host, timeout, threads}
}

func (scanner portScanner) GetOpenPortList(first, last int) []int {
	var rv []int
	l := sync.Mutex{}
	sem := make(chan bool, scanner.threads)
	for port := first; port <= last; port++ {
		sem <- true
		go func(port int) {
			if scanner.IsOpen(port) {
				l.Lock()
				rv = append(rv, port)
				l.Unlock()
			}
			<-sem
		}(port)
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}

	return rv
}

func (scanner portScanner) IsOpen(port int) bool {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", scanner.hostPort(port))
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), scanner.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func (scanner portScanner) hostPort(port int) string {
	return fmt.Sprintf("%s:%d", scanner.host, port)
}

func processingResult(host string, ports []int) {
	y, err := yaml.Marshal(ports)
	if err != nil {
		panic(err.Error())
	}
	if _, err := os.Stat("result/" + host + ".yaml"); os.IsNotExist(err) {
		_, err := os.Create("result/" + host + ".yaml")
		if err != nil {
			println(err)
		}
		err = ioutil.WriteFile("result/"+host+".yaml", y, 0644)
		if err != nil {
			println(err)
		}
		for _, p := range ports {
			fmt.Print(" ", p, "[open]")
			println(" --> ", DescribePort(p))
		}
	} else {
		fmt.Printf("Target %s was found inn an inventory\n", host)
		check := isResultsEqual(host, ports)
		if check != true {
			fmt.Printf("Something changed on host %s, updating inventory...\n", host)
			err = ioutil.WriteFile("result/"+host+".yaml", y, 0644)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("New scan found next ports:")
			for _, port := range ports {
				fmt.Print(" ", port, " [open]")
				fmt.Println(" --> ", DescribePort(port))
			}
		} else {
			fmt.Printf("Nothing changed on host %s since last scan. Please check your file %s.yaml\n", host, host)
		}
	}

}

func DescribePort(port int) string {
	switch {
	default:
		return UNKNOWN
	case port > 0:
		assumed := predictPort(port, knPorts)
		return assumed
	}

}

func predictPort(port int, data KnownPorts) string {
	description := "UNKNOWN"
	for _, e := range data.Services {
		if e.Port == port {
			description = e.Description
		}
	}
	if len(description) > 0 {
		return description
	}

	return description
}

func isResultsEqual(host string, ports []int) bool {
	var oldPorts []int
	source, err := ioutil.ReadFile("result/" + host + ".yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(source, &oldPorts)
	if err != nil {
		panic(err)
	}
	if len(ports) == len(oldPorts) {
		return true
	}
	return false
}

func portsFromConfig() KnownPorts {
	var ports KnownPorts
	source, err := ioutil.ReadFile("./knownPorts.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(source, &ports)
	if err != nil {
		panic(err)
	}
	return ports
}

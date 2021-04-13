package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var (
	strongSwanVersionRe = regexp.MustCompile(`(?m)Swan (.+)(, Lin)`)
	ipv4Re              = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	ipv4RePingable      = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){2}(\.(0))`)
	subnetRe            = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(/)([0-9]){1,2}`)
	establishedRe       = regexp.MustCompile(`ESTABLISHED`)
	tunnelAndChildRe    = regexp.MustCompile(`child:.+TUNNEL`)
	installedRe         = regexp.MustCompile(`INSTALLED`)
	nameEstablishedRe   = regexp.MustCompile(`^(.+?)(\[)`)
	nameChildTunnelRe   = regexp.MustCompile(`^(.+?)(\:)`)
	nameInstalledRe     = regexp.MustCompile(`^(.+?)(\{)`)
	bytesRe             = regexp.MustCompile(`(\d*)\sbytes_`)
)

type StatusAll struct {
	Version string `json:"version"`
	Tunnels map[string]Tunnel
}

// type Pingable string

// `json:"{#PINGABLE}`

type Tunnel struct {
	Name          string `json:"{#TUNNEL}"`
	LocalIp       string
	RemoteIp      string
	LocalSubnets  []string
	RemoteSubnets []string
	BytesIn       int
	BytesOut      int
	Count         int
}

func main() {
	a := flag.String("a", "", "discover or monitor")
	flag.Parse()

	stat, err := os.Stdin.Stat()
	if err != nil {
		log.Fatal(err)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		log.Fatal("Pipe here the output of ipsec statusall")
	}

	var sa StatusAll
	sa.Tunnels = make(map[string]Tunnel)
	lines, err := ReadStdIn()
	if err != nil {
		log.Fatalln(err)
	}
	sa.parse(lines)

	switch *a {
	case "discover":
		sa.discover()
	case "monitor":
		sa.monitor()
	default:
		flag.Usage()
	}
}

func (sa *StatusAll) monitor() {
	type tunnel struct {
		Name     string `json:"Name"`
		BytesIn  int    `json:"BytesIn"`
		BytesOut int    `json:"BytesOut"`
		Count    int    `json:"Count"`
	}
	m := make(map[string]tunnel)
	for k, v := range sa.Tunnels {
		t := tunnel{
			Name:     v.Name,
			BytesIn:  v.BytesIn,
			BytesOut: v.BytesOut,
			Count:    v.Count,
		}
		m[replaceHyphens(k)] = t
	}
	bb, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(bb))
}

func (sa *StatusAll) discover() {
	type tunnel struct {
		Name                  string `json:"{#TUNNEL}"`
		LocalIp               string `json:"{#LOCAL_PUBLIC_IP}"`
		RemoteIp              string `json:"{#REMOTE_PUBLIC_IP}"`
		LocalSubnet           string `json:"{#LOCAL_INTERNAL_SUBNET}"`
		RemoteSubnet          string `json:"{#REMOTE_INTERNAL_SUBNET}"`
		LocalPrivateEndpoint  string `json:"{#LOCAL_PINGABLE_ENDPOINT}"`
		RemotePrivateEndpoint string `json:"{#REMOTE_PINGABLE_ENDPOINT}"`
	}

	data := struct {
		TT []tunnel `json:"data"`
	}{}
	tt := []tunnel{}
	for _, v := range sa.Tunnels {
		for _, r := range v.RemoteSubnets {
			for _, l := range v.LocalSubnets {
				t := tunnel{}
				t.Name = replaceHyphens(v.Name)
				t.LocalIp = v.LocalIp
				t.LocalSubnet = l
				t.RemoteIp = v.RemoteIp
				t.RemoteSubnet = r
				t.LocalPrivateEndpoint = detectPingable(l)
				t.RemotePrivateEndpoint = detectPingable(r)
				tt = append(tt, t)
			}
		}
	}
	data.TT = tt
	bb, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(bb))
}

func (sa *StatusAll) parse(lines []string) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		ssv := parseStrongSwanVersion(line)
		if ssv != nil {
			sa.Version = *ssv
		}
		if hasTunnelAndChild(line) {
			name := parseName(*nameChildTunnelRe, line)
			if name != nil {
				t := Tunnel{
					Name: *name,
				}
				localsubnets, remotesubnets := parseSubnets(line)
				t.LocalSubnets = localsubnets
				t.RemoteSubnets = remotesubnets
				for _, l := range lines {
					l = strings.TrimSpace(l)
					if hasEstablished(l) {
						n := parseName(*nameEstablishedRe, l)
						if *n == *name {
							localip, remoteip := parseIps(l)
							t.LocalIp = localip
							t.RemoteIp = remoteip
						}
					}
					if hasBytes(l) {
						n := parseName(*nameInstalledRe, l)
						if *n == *name {
							bytesI, bytesO := parseBytes(l)
							t.BytesIn = bytesI
							t.BytesOut = bytesO
						}
					}
				}
				_, ok := sa.Tunnels[t.Name]
				if !ok {
					sa.Tunnels[t.Name] = t
				} else {
					t = sa.Tunnels[t.Name]
					t.Count++
					sa.Tunnels[t.Name] = t
				}
			}
		}
		if hasInstalled(line) {
			name := parseName(*nameInstalledRe, line)
			if name != nil {
				_, ok := sa.Tunnels[*name]
				if ok {
					t := sa.Tunnels[*name]
					t.Count++
					sa.Tunnels[*name] = t
				}
			}
		}
	}
}

func ReadStdIn() ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func StatusAllCmd() (string, error) {
	var (
		Stdout bytes.Buffer
		Stderr bytes.Buffer
	)

	// cmd := exec.Command("cat", "statusall.out")
	cmd := exec.Command("ipsec", "statusall")
	cmd.Stdout = &Stdout
	cmd.Stderr = &Stderr
	err := cmd.Run()
	if err != nil {
		return "", errors.New(Stderr.String())
	}
	return Stdout.String(), nil
}

func detectPingable(s string) string {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		log.Println(err)
		return ""
	}
	size, _ := ipnet.Mask.Size()
	if size == 32 || pingableIp(ipnet.IP.String()) {
		return ipnet.IP.String()
	}
	return replaceToPingable(ipnet.IP.String())
}

func replaceToPingable(s string) string {
	s = trimSuffix(s, "0")
	s = s + "1"
	return s
}

func trimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}

func parseStrongSwanVersion(str string) *string {
	matches := strongSwanVersionRe.FindStringSubmatch(str)
	if len(matches) != 3 {
		return nil
	}
	return &matches[1]
}

func hasEstablished(str string) bool {
	matches := establishedRe.FindStringSubmatch(str)
	if len(matches) > 0 {
		return true
	}
	return false
}

func hasInstalled(str string) bool {
	matches := installedRe.FindStringSubmatch(str)
	if len(matches) > 0 {
		return true
	}
	return false
}

func hasBytes(str string) bool {
	matches := bytesRe.FindAllStringSubmatch(str, -1)
	if len(matches) > 0 {
		return true
	}
	return false
}

func parseBytes(str string) (int, int) {
	matches := bytesRe.FindAllStringSubmatch(str, -1)
	if len(matches) == 2 {
		in, err := strconv.Atoi(matches[0][1])
		if err != nil {
			return 0, 0
		}
		out, err := strconv.Atoi(matches[1][1])
		if err != nil {
			return 0, 0
		}
		return in, out
	}
	return 0, 0
}

func hasChild(str, tunnelname string) bool {
	childRe := regexp.MustCompile(fmt.Sprintf(`(%s).+(%s)`, tunnelname, "child:"))
	matches := childRe.FindStringSubmatch(str)
	if len(matches) > 0 {
		return true
	}
	return false
}

func hasTunnelAndChild(str string) bool {
	matches := tunnelAndChildRe.FindStringSubmatch(str)
	if len(matches) > 0 {
		return true
	}
	return false
}

func parseIps(str string) (string, string) {
	subMatchAll := ipv4Re.FindAllString(str, -1)
	return subMatchAll[0], subMatchAll[2]
}

func pingableIp(str string) bool {
	subMatchAll := ipv4RePingable.FindAllString(str, -1)
	if len(subMatchAll) > 0 {
		return false
	}
	return true
}

func parseSubnets(str string) ([]string, []string) {
	var locals, remotes []string
	ss := strings.Split(str, "===")
	if len(ss) == 2 {
		localSubmatchAll := subnetRe.FindAllString(ss[0], -1)
		for _, l := range localSubmatchAll {
			locals = append(locals, l)
		}
		remoteSubmatchAll := subnetRe.FindAllString(ss[1], -1)
		for _, r := range remoteSubmatchAll {
			remotes = append(remotes, r)
		}
	}
	return locals, remotes
}

func parseName(re regexp.Regexp, str string) *string {
	matches := re.FindStringSubmatch(str)
	if len(matches) != 3 {
		return nil
	}
	return &matches[1]
}

func replaceHyphens(str string) string {
	return strings.Replace(str, "-", "_", -1)
}

func StringToLines(s string) (lines []string, err error) {
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	return
}

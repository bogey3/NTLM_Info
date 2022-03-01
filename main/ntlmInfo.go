package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const SERVER_NAME = 1
const DOMAIN_NAME = 2
const SERVER_FQDN = 3
const DOMAIN_FQDN = 4
const PARENT_DOMAIN = 5
const REQ_FOR_CHALLENGE = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
var REQ_FOR_CHALLENGE_BYTES = []byte{78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 7, 130, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

type targetStruct struct{
	targetURL *url.URL
	challenge type2ChallengeStruct
}

type type2ChallengeStruct struct{
	rawChallenge []byte
	serverName string
	domainName string
	serverFQDN string
	domainFQDN string
	parentDomain string
	osVersionNumber string
	osVersionString string
}

func (t *targetStruct)getChallenge(){
	switch t.targetURL.Scheme {
	case "http":
		t.getHTTPChallenge()
	case "https":
		t.getHTTPChallenge()
	case "rdp":
		t.getRDPChallenge()
	case "smtp":
		t.getSMTPChallenge()
	default:
		usage()
	}

}

func (t *targetStruct)getHTTPChallenge(){
	if proxy, err := getProxy(); err == nil{
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(&proxy)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	authType := getAuthType(t.targetURL)
	if strings.ToLower(authType) == "ntlm" || strings.ToLower(authType) == "negotiate" {
		wwwAuthHeader := authType + " " + REQ_FOR_CHALLENGE
		type1Request, _ := http.NewRequest("GET", t.targetURL.String(), nil)
		type1Request.Header.Add("Authorization", wwwAuthHeader)
		type2Response, _ := http.DefaultClient.Do(type1Request)
		type2Challenge := type2Response.Header.Get("Www-Authenticate")
		type2Challenge = type2Challenge[len(authType)+1:]
		if strings.Contains(type2Challenge, ",") {
			type2Challenge = type2Challenge[:strings.LastIndex(type2Challenge, ",")]
		}
		t.challenge.rawChallenge, _ = base64.StdEncoding.DecodeString(type2Challenge)
	} else {
		fmt.Println("This url does not support NTLM or Negotiate authentication.")
	}
}

func (t *targetStruct)getRDPChallenge(){
	if !strings.Contains(t.targetURL.Host, ":"){
		t.targetURL.Host = t.targetURL.Host + ":3389"
	}
	challenge := make([]byte, 2048)
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", t.targetURL.Host, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		NLAData := append(append([]byte{48, 55, 160, 3, 2, 1, 96, 161, 48, 48, 46, 48, 44, 160, 42, 4, 40}, REQ_FOR_CHALLENGE_BYTES...), []byte{0, 0, 10, 0, 99, 69, 0, 0, 0, 15}...)
		_, err = conn.Write(NLAData)
		if err == nil {
			readLen, _ := conn.Read(challenge)
			challenge = challenge[23:readLen]
			t.challenge.rawChallenge = challenge
		}
	}
	fmt.Println("Could not connect to RDP server")
}

func (t *targetStruct)getSMTPChallenge(){
	if !strings.Contains(t.targetURL.Host, ":"){
		t.targetURL.Host = t.targetURL.Host + ":25"
	}
	buffer := make([]byte, 1024)
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.Dial("tcp", t.targetURL.Host)
	if err == nil {
		conn.Read(buffer)
		conn.Write([]byte("EHLO test.com\r\n"))
		n, _ := conn.Read(buffer)
		data := string(buffer[:n])
		if strings.Contains(data, "NTLM") {
			conn.Write([]byte("AUTH NTLM " + REQ_FOR_CHALLENGE + "\r\n"))
			n, _ = conn.Read(buffer)
			data = string(buffer[:n])
			challengeStr := strings.Split(data, " ")[1]
			type2ChallengeBytes, _ := base64.StdEncoding.DecodeString(challengeStr)
			t.challenge.rawChallenge = type2ChallengeBytes

		} else {
			fmt.Println("This SMTP server does not support NTLM authentication.")
		}
	} else {
		fmt.Println("Could not connect to SMTP server")
	}
}

func (t *type2ChallengeStruct)decode() {
	offset := binary.LittleEndian.Uint16(t.rawChallenge[44:48])
	data := t.rawChallenge[offset:]
	for i := 0; i < 5; i++ {
		dataType := binary.LittleEndian.Uint16(data[0:2])
		dataLength := binary.LittleEndian.Uint16(data[2:4]) + 4
		text := strings.Replace(string(data[4:dataLength]), "\x00", "", -1)
		switch dataType {
		case SERVER_NAME:
			t.serverName = text
		case DOMAIN_NAME:
			t.domainName = text
		case SERVER_FQDN:
			t.serverFQDN = text
		case DOMAIN_FQDN:
			t.domainFQDN = text
		case PARENT_DOMAIN:
			t.parentDomain = text
		}
		data = data[dataLength:]
	}

	if offset > 48 {
		major := int(t.rawChallenge[48])
		minor := int(t.rawChallenge[49])
		build := int(binary.LittleEndian.Uint16(t.rawChallenge[50:52]))
		t.osVersionNumber = strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(build)
		switch strconv.Itoa(major) + "." + strconv.Itoa(minor) {
		case "5.0":
			t.osVersionString = "Windows 2000 (Build " + strconv.Itoa(build) + ")"
		case "5.1":
			t.osVersionString = "Windows XP/Server 2003 (R2) (Build " + strconv.Itoa(build) + ")"
		case "5.2":
			t.osVersionString = "Windows XP/Server 2003 (R2) (Build " + strconv.Itoa(build) + ")"
		case "6.0":
			t.osVersionString = "Windows Vista/Server 2008 (Build " + strconv.Itoa(build) + ")"
		case "6.1":
			t.osVersionString = "Windows 7/Server 2008 R2 (Build " + strconv.Itoa(build) + ")"
		case "6.2":
			t.osVersionString = "Windows 8/Server 2012 (Build " + strconv.Itoa(build) + ")"
		case "6.3":
			t.osVersionString = "Windows 8.1/Server 2012 R2 (Build " + strconv.Itoa(build) + ")"
		case "10.0":
			if build >= 22000 {
				t.osVersionString = "Windows 11/Server 2022 (Build " + strconv.Itoa(build) + ")"
			} else if build >= 20348 {
				t.osVersionString = "Windows 10/Server 2022 (Build " + strconv.Itoa(build) + ")"
			} else if build >= 17623 {
				t.osVersionString = "Windows 10/Server 2019 (Build " + strconv.Itoa(build) + ")"
			} else {
				t.osVersionString = "Windows 10/Server 2016 (Build " + strconv.Itoa(build) + ")"
			}
		default:
			t.osVersionString = strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(build)
		}
	}
}

func getAuthType(targetURL *url.URL) string {
	resp, _ := http.Get(targetURL.String())
	if resp.StatusCode == 401 {
		authHeader, ok := resp.Header["Www-Authenticate"]
		if ok {
			for _, header := range authHeader {
				if header == "Negotiate" || header == "NTLM" {
					return header
				}
			}
		}
	}
	return ""
}

func usage() {
	fmt.Println("NTLM Authentication Information Disclosure\n\n\t" + os.Args[0] + " https://mail.example.com/ews\n\t" + os.Args[0] + " smtp://mail.example.com\n\t" + os.Args[0] + " rdp://computer.example.com")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	var err error
	target := targetStruct{}
	target.targetURL, err = url.Parse(os.Args[1])

	if err != nil{
		fmt.Println(err)
		usage()
	}

	target.getChallenge()
	if target.challenge.rawChallenge != nil {
		target.challenge.decode()
		fmt.Printf("+%s+%s+\n", strings.Repeat("-", 19), strings.Repeat("-", 47))
		fmt.Printf("| %17s | %-45s |\n", "Server Name", target.challenge.serverName)
		fmt.Printf("| %17s | %-45s |\n", "Domain Name", target.challenge.domainName)
		fmt.Printf("| %17s | %-45s |\n", "Server FQDN", target.challenge.serverFQDN)
		fmt.Printf("| %17s | %-45s |\n", "Domain FQDN", target.challenge.domainFQDN)
		fmt.Printf("| %17s | %-45s |\n", "Parent Domain", target.challenge.parentDomain)
		fmt.Printf("| %17s | %-45s |\n", "OS Version Number", target.challenge.osVersionNumber)
		fmt.Printf("| %17s | %-45s |\n", "OS Version", target.challenge.osVersionString)
		fmt.Printf("+%s+%s+\n", strings.Repeat("-", 19), strings.Repeat("-", 47))
	}
	os.Exit(0)
}

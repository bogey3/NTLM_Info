package NTLM_Info

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

type TargetStruct struct {
	TargetURL *url.URL
	Challenge type2ChallengeStruct
}

type type2ChallengeStruct struct {
	RawChallenge []byte
	ServerName   string
	DomainName string
	ServerFQDN   string
	DomainFQDN      string
	ParentDomain    string
	OsVersionNumber string
	OsVersionString string
}

func (t *TargetStruct) GetChallenge() error {
	var err error

	switch t.TargetURL.Scheme {
	case "http":
		err = t.getHTTPChallenge()
	case "https":
		err = t.getHTTPChallenge()
	case "rdp":
		err = t.getRDPChallenge()
	case "smtp":
		err = t.getSMTPChallenge()
	default:
		return errors.New("Unrecognized URL scheme.")
	}

	if err == nil {
		t.Challenge.decode()

	}
	return err

}

func (t *TargetStruct) getHTTPChallenge() error {
	http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	wwwAuthHeader := "NTLM " + REQ_FOR_CHALLENGE
	type1Request, err := http.NewRequest("GET", t.TargetURL.String(), nil)
	if err == nil {
		type1Request.Header.Add("Authorization", wwwAuthHeader)
		type2Response, err := http.DefaultClient.Do(type1Request)
		if err == nil {
			type2Challenge := type2Response.Header.Get("Www-Authenticate")
			if type2Challenge == "" {
				fmt.Println("This url does not support NTLM or Negotiate authentication.")
				return errors.New("This url does not support NTLM or Negotiate authentication.")
			}
			type2Challenge = type2Challenge[strings.Index(type2Challenge, " ")+1:]
			if strings.Contains(type2Challenge, ",") {
				type2Challenge = type2Challenge[:strings.LastIndex(type2Challenge, ",")]
			}
			t.Challenge.RawChallenge, err = base64.StdEncoding.DecodeString(type2Challenge)
			return err
		}
	}
	return err
}

func (t *TargetStruct) getRDPChallenge() error {

	if !strings.Contains(t.TargetURL.Host, ":") {
		t.TargetURL.Host = t.TargetURL.Host + ":3389"
	}
	challenge := make([]byte, 2048)
	var pConn net.Conn
	var err error
	d := net.Dialer{Timeout: 10 * time.Second}
	pConn, err = d.Dial("tcp", t.TargetURL.Host)
	conn := tls.Client(pConn, &tls.Config{InsecureSkipVerify: true})

	if err == nil {
		NLAData := append(append([]byte{48, 55, 160, 3, 2, 1, 96, 161, 48, 48, 46, 48, 44, 160, 42, 4, 40}, REQ_FOR_CHALLENGE_BYTES...), []byte{0, 0, 10, 0, 99, 69, 0, 0, 0, 15}...)
		_, err = conn.Write(NLAData)
		if err == nil {
			readLen, err := conn.Read(challenge)
			if err == nil {
				challenge = challenge[23:readLen]
				t.Challenge.RawChallenge = challenge
			}
		}
	}
	return err
}

func (t *TargetStruct) getSMTPChallenge() error {
	if !strings.Contains(t.TargetURL.Host, ":") {
		t.TargetURL.Host = t.TargetURL.Host + ":25"
	}
	buffer := make([]byte, 1024)
	var conn net.Conn
	var err error
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err = d.Dial("tcp", t.TargetURL.Host)

	if err == nil {
		conn.Read(buffer)
		conn.Write([]byte("EHLO test.com\r\n"))
		n, _ := conn.Read(buffer)
		data := string(buffer[:n])
		if strings.Contains(data, "NTLM") {
			conn.Write([]byte("AUTH NTLM " + REQ_FOR_CHALLENGE + "\r\n"))
			n, err = conn.Read(buffer)
			if err == nil {
				data = string(buffer[:n])
				challengeStr := strings.Split(data, " ")[1]
				type2ChallengeBytes, err := base64.StdEncoding.DecodeString(challengeStr)
				if err == nil {
					t.Challenge.RawChallenge = type2ChallengeBytes
				}
			}
		} else {
			return errors.New("This SMTP server does not support NTLM authentication.")
		}
	}
	return err
}

func(t *TargetStruct) Print(){
	if t.Challenge.RawChallenge != nil {
		fmt.Printf("+%s+%s+\n", strings.Repeat("-", 19), strings.Repeat("-", 47))
		fmt.Printf("| %17s | %-45s |\n", "Server Name", t.Challenge.ServerName)
		fmt.Printf("| %17s | %-45s |\n", "Domain Name", t.Challenge.DomainName)
		fmt.Printf("| %17s | %-45s |\n", "Server FQDN", t.Challenge.ServerFQDN)
		fmt.Printf("| %17s | %-45s |\n", "Domain FQDN", t.Challenge.DomainFQDN)
		fmt.Printf("| %17s | %-45s |\n", "Parent Domain", t.Challenge.ParentDomain)
		fmt.Printf("| %17s | %-45s |\n", "OS Version Number", t.Challenge.OsVersionNumber)
		fmt.Printf("| %17s | %-45s |\n", "OS Version", t.Challenge.OsVersionString)
		fmt.Printf("+%s+%s+\n", strings.Repeat("-", 19), strings.Repeat("-", 47))
	}
}

func (t *type2ChallengeStruct) decode() {
	offset := binary.LittleEndian.Uint16(t.RawChallenge[44:48])
	data := t.RawChallenge[offset:]
	for i := 0; i < 5; i++ {
		dataType := binary.LittleEndian.Uint16(data[0:2])
		dataLength := binary.LittleEndian.Uint16(data[2:4]) + 4
		text := strings.Replace(string(data[4:dataLength]), "\x00", "", -1)
		switch dataType {
		case SERVER_NAME:
			t.ServerName = text
		case DOMAIN_NAME:
			t.DomainName = text
		case SERVER_FQDN:
			t.ServerFQDN = text
		case DOMAIN_FQDN:
			t.DomainFQDN = text
		case PARENT_DOMAIN:
			t.ParentDomain = text
		}
		data = data[dataLength:]
	}

	if offset > 48 {
		major := int(t.RawChallenge[48])
		minor := int(t.RawChallenge[49])
		build := int(binary.LittleEndian.Uint16(t.RawChallenge[50:52]))
		t.OsVersionNumber = strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(build)
		switch strconv.Itoa(major) + "." + strconv.Itoa(minor) {
		case "5.0":
			t.OsVersionString = "Windows 2000 (Build " + strconv.Itoa(build) + ")"
		case "5.1":
			t.OsVersionString = "Windows XP/Server 2003 (R2) (Build " + strconv.Itoa(build) + ")"
		case "5.2":
			t.OsVersionString = "Windows XP/Server 2003 (R2) (Build " + strconv.Itoa(build) + ")"
		case "6.0":
			t.OsVersionString = "Windows Vista/Server 2008 (Build " + strconv.Itoa(build) + ")"
		case "6.1":
			t.OsVersionString = "Windows 7/Server 2008 R2 (Build " + strconv.Itoa(build) + ")"
		case "6.2":
			t.OsVersionString = "Windows 8/Server 2012 (Build " + strconv.Itoa(build) + ")"
		case "6.3":
			t.OsVersionString = "Windows 8.1/Server 2012 R2 (Build " + strconv.Itoa(build) + ")"
		case "10.0":
			if build >= 22000 {
				t.OsVersionString = "Windows 11/Server 2022 (Build " + strconv.Itoa(build) + ")"
			} else if build >= 20348 {
				t.OsVersionString = "Windows 10/Server 2022 (Build " + strconv.Itoa(build) + ")"
			} else if build >= 17623 {
				t.OsVersionString = "Windows 10/Server 2019 (Build " + strconv.Itoa(build) + ")"
			} else {
				t.OsVersionString = "Windows 10/Server 2016 (Build " + strconv.Itoa(build) + ")"
			}
		default:
			t.OsVersionString = strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(build)
		}
	}
}

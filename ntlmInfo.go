package NTLM_Info

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const SERVER_NAME = 1
const DOMAIN_NAME = 2
const SERVER_FQDN = 3
const DOMAIN_FQDN = 4
const PARENT_DOMAIN = 5

const REQ_FOR_CHALLENGE = "TlRMTVNTUAABAAAAFYIIYgAAAAAoAAAAAAAAACgAAAAAAAAAAAAAAA=="

var REQ_FOR_CHALLENGE_BYTES = []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x62, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func createHTTPClients() (*http.Client, *http.Client) {

	http2EnabledClient := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	http2DisabledClient := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			TLSNextProto:    map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		},
	}

	return http2EnabledClient, http2DisabledClient
}

type TargetStruct struct {
	TargetURL *url.URL
	Challenge type2ChallengeStruct
}

type type2ChallengeStruct struct {
	RawChallenge    []byte
	ServerName      string
	DomainName      string
	ServerFQDN      string
	DomainFQDN      string
	ParentDomain    string
	OsVersionNumber string
}

func NewTarget(urlString string) (*TargetStruct, error) {
	targetURL, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	return &TargetStruct{targetURL, type2ChallengeStruct{}}, nil
}

func (t *TargetStruct) GetChallenge() error {
	var err error

	switch t.TargetURL.Scheme {
	case "http", "https":
		http2EnabledClient, http2DisabledClient := createHTTPClients()
		err = t.getHTTPChallenge(http2EnabledClient, http2DisabledClient)
	case "rdp":
		err = t.getRDPChallenge()
	case "smtp":
		err = t.getSMTPChallenge()
	case "smb":
		err = t.getSMBChallenge()
	default:
		return errors.New("Unrecognized URL scheme.")
	}

	if err == nil {
		t.Challenge.decode()

	}
	return err

}

func (t *TargetStruct) getHTTPChallenge(primaryClient *http.Client, secondaryClient *http.Client) error {
	baselineRequest, err := http.NewRequest("GET", t.TargetURL.String(), nil)
	authType := "Negotiate"
	if err == nil {
		baselineResponse, err := primaryClient.Do(baselineRequest)
		if err == nil {
			authHeader := baselineResponse.Header.Get("Www-Authenticate")
			if strings.Contains(authHeader, "NTLM") {
				authType = "NTLM"
			}
		}
	}

	wwwAuthHeader := fmt.Sprintf("%s %s", authType, REQ_FOR_CHALLENGE)
	type1Request, err := http.NewRequest("GET", t.TargetURL.String(), nil)
	if err == nil {
		type1Request.Header.Add("Authorization", wwwAuthHeader)
		type2Response, err := primaryClient.Do(type1Request)
		if err == nil {
			type2Challenge := type2Response.Header.Get("Www-Authenticate")
			if type2Challenge == "" {
				return errors.New("This url does not support NTLM or Negotiate authentication.")
			}
			type2Challenge = type2Challenge[strings.Index(type2Challenge, " ")+1:]
			if strings.Contains(type2Challenge, ",") {
				type2Challenge = type2Challenge[:strings.LastIndex(type2Challenge, ",")]
			}
			t.Challenge.RawChallenge, err = base64.StdEncoding.DecodeString(type2Challenge)
			return err
		} else {
			if strings.Contains(err.Error(), "HTTP_1_1_REQUIRED") {
				return t.getHTTPChallenge(secondaryClient, primaryClient)
			}
			return err
		}
	}
	return err
}

func (t *TargetStruct) getSMBChallenge() error {
	if !strings.Contains(t.TargetURL.Host, ":") {
		t.TargetURL.Host = t.TargetURL.Host + ":445"
	}

	negotiateProtocolRequest := []byte{0x00, 0x00, 0x00, 0xe8, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x53, 0x2b, 0x0b, 0x2c, 0xe2, 0x12, 0x87, 0x4b, 0xa6, 0x8c, 0xfe, 0x6e, 0xc1, 0xe5, 0x59, 0x0c, 0x70, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03, 0x00, 0x00, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x3d, 0x91, 0xef, 0x15, 0x2f, 0x8c, 0x8a, 0x3a, 0xc8, 0x62, 0x14, 0xc2, 0x82, 0x59, 0x5e, 0x30, 0x83, 0x83, 0x25, 0x3e, 0x74, 0x4b, 0xaa, 0x93, 0x4b, 0x4d, 0xa6, 0xc5, 0xf5, 0x64, 0xdd, 0x37, 0x00, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x37, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x32, 0x00, 0x31, 0x00}
	smb2Header := []byte{0x00, 0x00, 0x00, 0xa2, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a, 0x04, 0x28}

	buffer := make([]byte, 1024)
	var conn net.Conn
	var err error
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err = d.Dial("tcp", t.TargetURL.Host)

	if err == nil {
		conn.Write(negotiateProtocolRequest)
		n, _ := conn.Read(buffer)
		data := buffer[:n]
		conn.Write(append(smb2Header, REQ_FOR_CHALLENGE_BYTES...))
		n, _ = conn.Read(buffer)
		data = buffer[:n]
		if bytes.Contains(data, []byte("NTLMSSP\x00")) {
			t.Challenge.RawChallenge = data[bytes.Index(data, []byte("NTLMSSP\x00")):]
		} else {
			return errors.New("This SMB server does not support NTLM authentication.")
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
		NLAData := append(append([]byte{48, 55, 160, 3, 2, 1, 96, 161, 48, 48, 46, 48, 44, 160, 42, 4, 40}, REQ_FOR_CHALLENGE_BYTES...))
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

func (t *TargetStruct) Print() {
	if t.Challenge.RawChallenge != nil {
		column2Length := int(math.Max(45, float64(len(t.TargetURL.String()))))
		formatString := fmt.Sprintf("| %%17s | %%-%ds |\n", column2Length)
		fmt.Printf("+%s+%s+\n", strings.Repeat("-", 19), strings.Repeat("-", column2Length+2))
		fmt.Printf(formatString, "URL", t.TargetURL.String())
		fmt.Printf("+%s+%s+\n", strings.Repeat("-", 19), strings.Repeat("-", column2Length+2))
		fmt.Printf(formatString, "Server Name", t.Challenge.ServerName)
		fmt.Printf(formatString, "Domain Name", t.Challenge.DomainName)
		fmt.Printf(formatString, "Server FQDN", t.Challenge.ServerFQDN)
		fmt.Printf(formatString, "Domain FQDN", t.Challenge.DomainFQDN)
		fmt.Printf(formatString, "Parent Domain", t.Challenge.ParentDomain)
		fmt.Printf(formatString, "OS Version Number", t.Challenge.OsVersionNumber)
		fmt.Printf("+%s+%s+\n", strings.Repeat("-", 19), strings.Repeat("-", column2Length+2))
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
		t.OsVersionNumber = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}
}

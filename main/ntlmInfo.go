package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func getAuthType(authUrl string) string{
	resp, _ := http.Get(authUrl)
	if resp.StatusCode == 401{
		authHeader, ok := resp.Header["Www-Authenticate"]
		if ok{
			for _, header := range authHeader{
				if header == "Negotiate" || header == "NTLM"{
					return header
				}
			}
		}
	}
	return ""
}

func pad(inputArray []byte, length int) []byte{
	out := make([]byte, len(inputArray))
	copy(out, inputArray)
	for i:= len(inputArray); i<length; i++{
		out = append(out, byte(0))
	}
	return out
}

func httpType2(ntlmUrl string) []byte{

	authType := getAuthType(ntlmUrl)
	if strings.ToLower(authType) == "ntlm" || strings.ToLower(authType) == "negotiate" {
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
		wwwAuthHeader := authType + " " + requstForChallengeString
		type1Request, _ := http.NewRequest("GET", ntlmUrl, nil)
		type1Request.Header.Add("Authorization", wwwAuthHeader)
		type2Response, _ := client.Do(type1Request)
		type2Challenge := type2Response.Header.Get("Www-Authenticate")
		type2Challenge = type2Challenge[len(authType)+1:]
		if strings.Index(type2Challenge, ",") != -1 {
			type2Challenge = type2Challenge[:strings.LastIndex(type2Challenge, ",")]
		}
		type2ChallengeBytes, _ := base64.StdEncoding.DecodeString(type2Challenge)
		return type2ChallengeBytes
	}else{
		fmt.Println("This url does not support NTLM or Negotiate authentication.")
	}
	return nil
}

func rdpType2(ntlmHost string, port string) []byte{
	challenge := make([]byte, 2048)
	d := net.Dialer{Timeout:10 * time.Second}
	conn, err := tls.DialWithDialer(&d,"tcp", ntlmHost + ":" + port, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		NLAData := append(append([]byte{48, 55, 160, 3, 2, 1, 96, 161, 48, 48, 46, 48, 44, 160, 42, 4, 40}, requestForChallenge...), []byte{0, 0, 10, 0, 99, 69, 0, 0, 0, 15}...)
		conn.Write(NLAData)
		len, _ := conn.Read(challenge)
		challenge = challenge[23:len]
		return challenge
	}
	fmt.Println("Could not connect to RDP server")
	return nil
}


func smtpType2(ntlmHost string, port string) []byte{
	buffer := make([]byte, 1024)
	d := net.Dialer{Timeout:10 * time.Second}
	conn, err := d.Dial("tcp", ntlmHost + ":" + port)
	if err == nil{
		conn.Read(buffer)
		conn.Write([]byte("EHLO test.com\r\n"))
		n, _ := conn.Read(buffer)
		data := string(buffer[:n])
		if strings.Contains(data, "NTLM"){
			conn.Write([]byte("AUTH NTLM " + requstForChallengeString + "\r\n"))
			n, _ = conn.Read(buffer)
			data = string(buffer[:n])
			challengeStr := strings.Split(data, " ")[1]
			type2ChallengeBytes, _ := base64.StdEncoding.DecodeString(challengeStr)
			return type2ChallengeBytes

		}else{
			fmt.Println("This SMTP server does not support NTLM authentication.")
		}
	}else{
		fmt.Println("Could not connect to SMTP server")
	}
	return nil
}


func decodeChallenge(challenge []byte, offset uint16) [6][2]string{
	data := challenge[offset:]
	types := [6]string{"Server Name:    ", "Domain Name:    ", "Server FQDN:    ", "Domain FQDN:    ", "Parent Domain:  ", "OS Version:     "}
	dataOut := [6][2]string{}
	for i := 0; i<5; i++{
		index := binary.LittleEndian.Uint16(pad(data[0:2], 4))-1
		if index != 6 {
			dataType := types[index]
			dataLength := binary.LittleEndian.Uint16(pad(data[2:4], 4)) + 4
			dataOut[i][0] = dataType
			text := string(data[4:dataLength])
			text = strings.Replace(text, "\x00", "", -1)
			dataOut[i][1] = text
			data = data[dataLength:]
		}
	}

	if offset > 48{
		dataOut[5][0] = types[5]
		major := int(challenge[48])
		minor := int(challenge[49])
		build := int(binary.LittleEndian.Uint16(pad(challenge[50:52], 4)))
		majorMinor := ""
		switch strconv.Itoa(major) + "." + strconv.Itoa(minor){
		case "5.0":
			majorMinor = "Windows 2000 (Build " + strconv.Itoa(build) +")"
		case "5.1":
			majorMinor = "Windows XP/Server 2003 (R2) (Build " + strconv.Itoa(build) +")"
		case "5.2":
			majorMinor = "Windows XP/Server 2003 (R2) (Build " + strconv.Itoa(build) +")"
		case "6.0":
			majorMinor = "Windows Vista/Server 2008 (Build " + strconv.Itoa(build) +")"
		case "6.1":
			majorMinor = "Windows 7/Server 2008 R2 (Build " + strconv.Itoa(build) +")"
		case "6.2":
			majorMinor = "Windows 8/Server 2012 (Build " + strconv.Itoa(build) +")"
		case "6.3":
			majorMinor = "Windows 8.1/Server 2012 R2 (Build " + strconv.Itoa(build) +")"
		case "10.0":
			if build >= 17623 {
				majorMinor = "Windows 10/Server 2019 (Build " + strconv.Itoa(build) +")"
			}else{
				majorMinor = "Windows 10/Server 2016 (Build " + strconv.Itoa(build) +")"
			}
		default:
			majorMinor = strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(build)
		}
		dataOut[5][1] = majorMinor


	}
	return dataOut
}

func usage(){
	fmt.Println("NTLM Authentication Information Disclosure\n\n\t" + os.Args[0] + " https://mail.example.com/ews\n\t" + os.Args[0] + " smtp://mail.example.com\n\t" + os.Args[0] + " rdp://computer.example.com")
	os.Exit(1)
}

var requestForChallenge = []byte{78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 7, 130, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var requstForChallengeString = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="

func main()  {
	//Test for correct number of command line arguments, and presence of "://" in argument, otherwise print help
	if len(os.Args) != 2 || !strings.Contains(os.Args[1], "://"){
		usage()
	}

	challenge := []byte{}
	targetUrl := os.Args[1]
	protocol := targetUrl[:strings.Index(targetUrl, "://")]

	//Switch statement to use the correct function to retrieve the NTLM challenge based on the protocol provided
	switch protocol {
	case "http":
		challenge = httpType2(targetUrl)
	case "https":
		//Allow the use of invalid HTTPS certificates
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		challenge = httpType2(targetUrl)
	case "rdp":
		urlAndPort := strings.Split(targetUrl, ":")
		if len(urlAndPort) == 2{
			urlAndPort = append(urlAndPort, "3389")
		}
		challenge = rdpType2(strings.Replace(urlAndPort[1], "//", "", 1), urlAndPort[2])
	case "smtp":
		urlAndPort := strings.Split(targetUrl, ":")
		if len(urlAndPort) == 2{
			urlAndPort = append(urlAndPort, "25")
		}
		challenge = smtpType2(strings.Replace(urlAndPort[1], "//", "", 1), urlAndPort[2])
	default:
		usage()
	}

	if challenge != nil{
		offset := binary.LittleEndian.Uint16(challenge[44:48])
		data := decodeChallenge(challenge, offset)
		for _, value := range data {
			if value[0] + value[1] != "" {
				fmt.Println(value[0] + value[1])
			}
		}

	}

	os.Exit(0)
}
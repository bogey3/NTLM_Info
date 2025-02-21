# NTLMSSP Information Disclosure

This module was written using Go version 1.15.5, other versions will likely work but are not tested.

This module can be used to extract information using the NTLMSSP challenge provided during NTLM authentication.

## How to use this module
This module can retrieve NTLMSSP information from HTTP, SMTP, and RDP servers.

Below is a simple sample program that uses this module:
```
package main

import (
	"fmt"
	"github.com/bogey3/NTLM_Info"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Please provide a URL as an argument.")
		return
	}

	input := os.Args[1]
	target, err := NTLM_Info.NewTarget(input)
	if err != nil {
		fmt.Println(err)
		return
	}
	target.GetChallenge()
	target.Print()

}
```

The output should be as follows:
```
+-------------------+-----------------------------------------------+
|               URL | http://example.com/ews                        |
+-------------------+-----------------------------------------------+
|       Server Name | HOSTNETBIOS                                   |
|       Domain Name | CHILDDOMAIN                                   |
|       Server FQDN | hostnetbios.childdomain.parentdomain.tld      |
|       Domain FQDN | childdomain.parentdomain.tld                  |
|     Parent Domain | parentdomain.tld                              |
| OS Version Number | 10.0.19041                                    |
|        OS Version | Windows 10/Server 2019 (Build 19041)          |
+-------------------+-----------------------------------------------+
```

## Sources
Much of the information used to create this software came from this excellent in depth page on the NTLMSSP protocol.

http://davenport.sourceforge.net/ntlm.html

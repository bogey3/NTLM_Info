# NTLMSSP Information Disclosure

This program was written using Go version 1.15.5, other versions will likely work but are not tested.

This program can be used to extract information using the NTLMSSP challenge provided during NTLM authentication.

## How to compile
Depending on your host OS compile instruction may vary slightly, however they should be quite similar.

You can compile this with a simple `go build /path/to/main/directory` on Linux or Windows.

If your current directory when running the command is the main directory, you can simply run `go build .`.


## How to use this program
Once compiled this software will take one argument as the target URL.

Below are a few examples on how to run this software:
```
ntlmInfo https://mail.domain.com/ews
ntlmInfo smtp://mail.domain.com
ntlmInfo smtp://mail.domain.com:2525
ntlmInfo rdp://192.168.0.10
ntlmInfo rdp://192.168.0.10:4489
```

If a port is not specified the default will be used as follows:
```
RDP:   3389
SMTP:  25
HTTP:  80
HTTPS: 443
```

The output should be as follows:
```
Domain Name:    CHILDDOMAIN
Server Name:    HOSTNETBIOS
Domain FQDN:    childdomain.parentdomain.tld
Server FQDN:    hostnetbios.childdomain.parentdomain.tld
Parent Domain:  parentdomain.tld
OS Version:     Windows 10/Server 2019 (Build 19041)
```

## Sources
Much of the information used to crete this software came from this excellent in depth page on the NTLMSSP protocol.

http://davenport.sourceforge.net/ntlm.html
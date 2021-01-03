package main

import (
	"errors"
	"net/url"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

type WINHTTP_CURRENT_USER_IE_PROXY_CONFIG struct {
	fAutoDetect       bool
	lpszAutoConfigUrl *uint16
	lpszProxy         *uint16
	lpszProxyBypass   *uint16
}

func GoWString(s *uint16) string {
	if s == nil {
		return ""
	}
	p := (*[1<<30 - 1]uint16)(unsafe.Pointer(s))
	sz := 0
	for p[sz] != 0 {
		sz++
	}
	return string(utf16.Decode(p[:sz:sz]))
}

func getProxy() (url.URL, error) {
	//Use Winhttp.dll to check the IE proxy config for current user
	winHttpApi := syscall.NewLazyDLL("Winhttp.dll")
	WinHttpGetDefaultProxyConfiguration := winHttpApi.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	out := WINHTTP_CURRENT_USER_IE_PROXY_CONFIG{}
	WinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&out)))
	proxyServer := GoWString(out.lpszProxy)
	if proxyServer != "" {
		proxyServer := GoWString(out.lpszProxy)
		parsedUrl, err := url.Parse("http://" + proxyServer)
		if err == nil {
			return *parsedUrl, nil
		}
	}
	return url.URL{}, errors.New("No Proxy Found")
}

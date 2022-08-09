package main

import (
	"errors"
	"net/url"
	"os"
)

func getProxy() (url.URL, error) {
	//Check the http_proxy environment variable for a proxy
	proxyUrl := os.Getenv("http_proxy")
	if proxyUrl != "" {
		parsedUrl, err := url.Parse(proxyUrl)
		if err == nil {
			return *parsedUrl, nil
		}
	}
	return url.URL{}, errors.New("No Proxy Found")
}

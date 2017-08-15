package auth

import (
	"net/http"
	"fmt"
	"strings"
)

var skip = []string{
	"swagger",
	"favicon.ico",
}

func AuthenticationHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri := r.RequestURI
		for _, element := range skip {
			if strings.Contains(strings.ToLower(uri), element) {
				h.ServeHTTP(w ,r)
				return
			}
		}

		fmt.Println(r.RequestURI)
		appid := r.Header.Get("Grpc-Metadata-appkey")
		if appid != "ctn" {
			appid = r.Header.Get("appkey")
		}
		if appid != "ctn" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 - Unauthorized operation\n"))
			return
		}
		h.ServeHTTP(w ,r)
	})
}


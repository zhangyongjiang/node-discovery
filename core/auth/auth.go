package auth

import (
	"net/http"
	"fmt"
	"strings"
	"encoding/hex"
	"golang.org/x/net/context"
	"google.golang.org/grpc/peer"
	"crypto/x509"
	"google.golang.org/grpc/credentials"
	gw "sancus/protos/communication"
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

func RetrieveClientFromContext(ctx context.Context) (*gw.Client)  {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}

	client := new(gw.Client)
	if peer == nil || peer.AuthInfo == nil {
		return client
	}

	tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
	v := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
	fmt.Printf("%v - %v\n", peer.Addr.String(), v)
	for _, v := range tlsInfo.State.PeerCertificates {
		pubkey, err := x509.MarshalPKIXPublicKey(v.PublicKey)
		if err != nil {
			client.Id = hex.EncodeToString(pubkey)
		}
	}

	return client
}


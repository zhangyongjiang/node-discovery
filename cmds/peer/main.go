package main

import (
	"time"
	"fmt"
	"crypto/tls"
	"crypto/x509"
	"discovery/core/peer"
	"discovery/core/auth"
)

func main() {
	signKey, signCert, caPEM, _ := auth.GenCertificateAuthorityECDSA("cmds/certs/Org1")

	_ , serverKeyPEM, serverCertPEM, _ := auth.GenServerCertificateECDSA("cmds/certs/Org1-server1", signKey, signCert)

	_ , keyBytesClient, certBytesClient, _ := auth.GenClientCertificateECDSA("cmds/certs/Org1-client1", signKey, signCert)
	clientCert, _ := tls.X509KeyPair(certBytesClient, keyBytesClient)

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM)

	clientTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	secureServerConfig := auth.SecureServerConfig{
			UseTLS:            true,
			ServerCertificate: serverCertPEM,
			ServerKey:         serverKeyPEM,
			RequireClientCert: true,
			ClientRootCAs:     [][]byte{caPEM},
	}

	addr := "localhost:9876"
	peerService := peer.NewPeerService(addr, secureServerConfig, clientTlsConfig)
	peerService.AddPeer(&peer.Peer{
		Addr: addr,
	})

	fmt.Println("hi")
	for {
		time.Sleep(10)
	}

}


package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	testpb "discovery/core/auth/grpc"
	"discovery/core/auth"
	//"encoding/pem"
	//"crypto/ecdsa"
	//"reflect"
)

type SecureServerConfig struct {
	//PEM-encoded X509 public key to be used by the server for TLS communication
	ServerCertificate []byte
	//PEM-encoded private key to be used by the server for TLS communication
	ServerKey []byte
	//Set of PEM-encoded X509 certificate authorities to optionally send
	//as part of the server handshake
	ServerRootCAs [][]byte
	//Set of PEM-encoded X509 certificate authorities to use when verifying
	//client certificates
	ClientRootCAs [][]byte
	//Whether or not to use TLS for communication
	UseTLS bool
	//Whether or not TLS client must present certificates for authentication
	RequireClientCert bool
}


var timeout = time.Second * 1

//test server to be registered with the GRPCServer
type testServiceServer struct{}

func (tss *testServiceServer) EmptyCall(context.Context, *testpb.Empty) (*testpb.Empty, error) {
	return new(testpb.Empty), nil
}

//invoke the EmptyCall RPC
func invokeEmptyCall(address string, dialOptions []grpc.DialOption) (*testpb.Empty, error) {

	//add DialOptions
	dialOptions = append(dialOptions, grpc.WithBlock())
	dialOptions = append(dialOptions, grpc.WithTimeout(timeout))
	//create GRPC client conn
	clientConn, err := grpc.Dial(address, dialOptions...)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer clientConn.Close()

	//create GRPC client
	client := testpb.NewTestServiceClient(clientConn)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//invoke service
	empty, err := client.EmptyCall(ctx, new(testpb.Empty))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return empty, nil
}


//utility function for testing client / server communication using TLS
func runMutualAuth(address string,  config  auth.SecureServerConfig,  clientTlsConfig *tls.Config) error {

	//loop through all the test servers

		//create listener
		lis, err := net.Listen("tcp", address)
		if err != nil {
			fmt.Println(err)
			return err
		}

		//create GRPCServer
		srv, err := auth.NewGRPCServerFromListener(lis, config)
		if err != nil {
			fmt.Println(err)
			return err
		}

		//register the GRPC test server and start the GRPCServer
		testpb.RegisterTestServiceServer(srv.Server(), &testServiceServer{})
		go srv.Start()
		defer srv.Stop()
		//should not be needed but just in case
		time.Sleep(10 * time.Millisecond)

		//loop through all the trusted clients

			//invoke the EmptyCall service
			_, err = invokeEmptyCall(address,
				[]grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(clientTlsConfig))})
			//we expect success from trusted clients
			if err != nil {
				fmt.Printf("Trusted client test failed: %s", err)
				return err
			} else {
				fmt.Printf("Trusted client successfully connected to %s", address)
			}


	return nil
}


func loadCerts() (caPEM []byte, serverKeyPEM []byte, serverCertPEM []byte, clientCert tls.Certificate) {
	caPEM, _ = ioutil.ReadFile("cmds/certs/Org1-cert.pme")

	//loop through and load servers
	serverKeyPEM, _ = ioutil.ReadFile("cmds/certs/Org1-server1-key.pme")
	serverCertPEM, _ = ioutil.ReadFile("cmds/certs/Org1-server1-cert.pme")

	clientCert, _ = auth.LoadTLSKeyPairFromFile("cmds/certs/Org1-client1-key.pme",
		"cmds/certs/Org1-client1-cert.pme")
	//privKey := reflect.ValueOf(clientCert.PrivateKey).Interface().(*ecdsa.PrivateKey)
	//fmt.Println(privKey.PublicKey)

	//certPEMBlock, err := ioutil.ReadFile("cmds/certs/Org1-client1-cert.pme")
	//if(err != nil) {
	//	fmt.Println(err)
	//}
	//block, rest := pem.Decode(certPEMBlock)
	//fmt.Println(block)
	//fmt.Println(rest)

	return caPEM, serverKeyPEM, serverCertPEM, clientCert
}

func createCerts() (caPEM []byte, serverKeyPEM []byte, serverCertPEM []byte, clientCert tls.Certificate) {
	signKey, signCert, caPEM, _ := auth.GenCertificateAuthorityECDSA("Org1")
	_ , keyBytesServer, certBytesServer, _ := auth.GenServerCertificateECDSA("Org1-server1", signKey, signCert)
	_ , keyBytesClient1, certBytesClient1, _ := auth.GenClientCertificateECDSA("Org1-client1", signKey, signCert)

	auth.GenClientCertificateECDSA("Org1-client2", signKey, signCert)

	clientTlsCert, _ := tls.X509KeyPair(certBytesClient1, keyBytesClient1)

	return caPEM, keyBytesServer, certBytesServer, clientTlsCert;
}

func main() {
	//caPEM, serverKeyPEM, serverCertPEM, clientCert := loadCerts()
	caPEM, serverKeyPEM, serverCertPEM, clientCert := createCerts()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM)

	clientTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	runMutualAuth(
		fmt.Sprintf("localhost:%d", 9876),

		auth.SecureServerConfig{
			UseTLS:            true,
			ServerCertificate: serverCertPEM,
			ServerKey:         serverKeyPEM,
			RequireClientCert: true,
			ClientRootCAs:     [][]byte{caPEM},
		},

		clientTlsConfig)
}

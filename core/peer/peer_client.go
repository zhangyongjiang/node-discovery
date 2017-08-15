package peer

import (
	"fmt"
	"golang.org/x/net/context"

	"crypto/tls"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var timeout = time.Second * 1

type peerClient struct {
	tlsConfig *tls.Config
}

func NewPeerCleint(tlsConfig *tls.Config) *peerClient {
	p := &peerClient{
		tlsConfig: tlsConfig,
	}
	return p
}

func (pc *peerClient) invokePingCall(address string) (*PingMsg, error) {
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(pc.tlsConfig))}
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
	client := NewPeerServiceClient(clientConn)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//invoke service
	resp, err := client.Ping(ctx, new(PingMsg))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return resp, nil
}


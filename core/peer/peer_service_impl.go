package peer

import (
	"net"
	"discovery/core/auth"
	"fmt"
	"golang.org/x/net/context"
	"crypto/tls"
	"time"
	"google.golang.org/grpc"
)

type peerServiceImpl struct {
	secureServerConfig auth.SecureServerConfig
	addr string
	clientTlsConfig *tls.Config
	peers []*Peer

	grpcServer *grpc.Server
}

func NewPeerService(addr string, secureServerConfig auth.SecureServerConfig, clientTlsConfig *tls.Config) *peerServiceImpl {
	p := &peerServiceImpl{
		addr: addr,
		secureServerConfig: secureServerConfig,
		clientTlsConfig: clientTlsConfig,
		peers: []*Peer{},
	}
	p.start()
	return p
}

func (ps *peerServiceImpl)AddPeer(peer *Peer) {
	ps.peers = append(ps.peers, peer)
}

func (ps *peerServiceImpl)GrpcServer() *grpc.Server {
	return ps.grpcServer
}

func (ps *peerServiceImpl)Peers() []*Peer {
	return ps.peers
}

func (ps *peerServiceImpl)start() error {
	//create listener
	lis, err := net.Listen("tcp", ps.addr)
	if err != nil {
		fmt.Println(err)
		return err
	}

	//create GRPCServer
	srv, err := auth.NewGRPCServerFromListener(lis, ps.secureServerConfig)
	if err != nil {
		fmt.Println(err)
		return err
	}
	ps.grpcServer = srv.Server()

	//register the GRPC test server and start the GRPCServer
	RegisterPeerServiceServer(srv.Server(), ps)
	go func() {
		err = srv.Start()
		defer func() {
			fmt.Println("======== grpc server stopped")
			srv.Stop()
		}()
		if err != nil {
			fmt.Printf("============ server start error %v", err)
		}
	}()

	go ps.checkPeerStatus()

	return nil
}

func (ps *peerServiceImpl) checkPeerStatus()  {
	timer := time.NewTicker(time.Second * 10)
	for {
		<-timer.C
		for _, pr := range ps.peers {
			client := NewPeerCleint(ps.clientTlsConfig)
			_, err := client.invokePingCall(pr.Addr)
			if err != nil {
				pr.Status = PeerStatusDisconnected
			} else {
				pr.Status = PeerStatusConnected
			}
			fmt.Printf("Peer %s status %d\n", pr.Addr, pr.Status)
		}
	}
	timer.Stop()
}

func (ps *peerServiceImpl) Ping(ctx context.Context, pm *PingMsg) (*PingMsg, error) {
	fmt.Println("ping...")
	return pm, nil
}


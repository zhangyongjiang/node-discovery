package peer

import (
	"google.golang.org/grpc"
)

type PeerStatus int
const (
	PeerStatusCreated PeerStatus = 1 + iota
	PeerStatusConnected
	PeerStatusDisconnected
)

type Peer struct {
	Status PeerStatus
	Addr string
}

type PeerService interface {
	GrpcServer() *grpc.Server
	AddPeer(peer *Peer)
	Peers() []*Peer
}

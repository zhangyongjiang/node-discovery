package auth

import (
	"sancus/protos/common"
	"sancus/protos/communication"
	"encoding/base64"
	"crypto/sha256"
	"github.com/golang/protobuf/proto"
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"crypto/ecdsa"
	"fmt"
	"errors"
	"reflect"
	"google.golang.org/grpc/peer"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

func HashOfTransaction(b *common.Transaction) string {
	return HashOfTransactionReq(b.EndorsedProposal.Proposal.Tran.TransactionReq)
}

func HashOfTransactionReq(b *common.TransactionReq) string {
	return Hash64(b)
}

func HashOfBlock(b *common.Block, trans []*common.Transaction) string {
	return Hash64(&communication.BlockWithTrans{
		Block: b,
		Trans: trans,
	})
}

func Hash(pb proto.Message) []byte {
	bytes, _ := proto.Marshal(pb)
	h := sha256.New()
	h.Write(bytes)
	b := h.Sum(nil)
	return b
}

func Hash64(pb proto.Message) string {
	return base64.URLEncoding.EncodeToString(Hash(pb))
}

func RsaSignMessage(pb proto.Message, secret *rsa.PrivateKey) (string, error)  {
	return RsaSign(Hash(pb), secret)
}

func RsaVerifyMessage(pb proto.Message, signature string, key *rsa.PublicKey) error {
	bytes, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	return RsaVerify(Hash(pb), bytes, key)
}

func RsaSign(digest []byte, secret *rsa.PrivateKey) (string, error)  {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	signature, err := rsa.SignPSS(rand.Reader, secret, crypto.SHA256, digest, &opts)
	return base64.URLEncoding.EncodeToString(signature), err;
}

func RsaVerify(hashed []byte, signature []byte, key *rsa.PublicKey) error {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	return rsa.VerifyPSS(key, crypto.SHA256, hashed, signature, &opts)
}

func EcdsaSignMessage(pb proto.Message, secret *ecdsa.PrivateKey) ([]byte, error)  {
	return EcdsaSign(Hash(pb), secret)
}

func EcdsaVerifyMessage(pb proto.Message, signature []byte, key *ecdsa.PublicKey) error {
	return EcdsaVerify(Hash(pb), signature, key)
}

func EcdsaSign(digest []byte, secret *ecdsa.PrivateKey) ([]byte, error)  {
	r, s, err := ecdsa.Sign(rand.Reader, secret, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = ToLowS(&secret.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return MarshalECDSASignature(r, s)
}

func EcdsaVerify(digest []byte, signature []byte, key *ecdsa.PublicKey) error {
	r, s, err := UnmarshalECDSASignature(signature)
	if err != nil {
		return err
	}

	lowS, err := IsLowS(key, s)
	if err != nil {
		return err
	}

	if !lowS {
		return fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, curveHalfOrders[key.Curve])
	}

	ok := ecdsa.Verify(key, digest, r, s)
	if ok {
		return nil
	}

	return errors.New("verify failed");
}

func GetPublicKeyFromContext(ctx context.Context) *ecdsa.PublicKey {
	peer, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
		for _, v := range tlsInfo.State.PeerCertificates {
			pubKey := reflect.ValueOf(v.PublicKey).Interface().(*ecdsa.PublicKey)
			return pubKey
		}
	}
	return nil
}


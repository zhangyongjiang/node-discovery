package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

//default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

//default template for X509 certificates
func x509Template() (x509.Certificate, error) {

	//generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return x509.Certificate{}, err
	}

	now := time.Now()
	//basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour), //~ten years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	return x509, nil

}

//generate an EC private key (P256 curve)
func genKeyECDSA(name string) (*ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)

	//write key out to file
	if true {
		keyFile, err := os.OpenFile(name+"-key.pme", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, nil, err
		}
		pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		keyFile.Close()
	}

	privByts := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return priv, privByts, nil
}

//generate a signed X509 certficate using ECDSA
func genCertificateECDSA(name string, template, parent *x509.Certificate, pub *ecdsa.PublicKey,
	priv *ecdsa.PrivateKey) (*x509.Certificate, []byte, error) {

	//create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	//write cert out to file
	if true {
		certFile, err := os.Create(name + "-cert.pme")
		if err != nil {
			return nil, nil, err
		}
		//pem encode the cert
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		certFile.Close()
	}

	inMemCertBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return x509Cert, inMemCertBytes, nil
}

//generate an EC certificate appropriate for use by a TLS server
func GenServerCertificateECDSA(name string, signKey *ecdsa.PrivateKey, signCert *x509.Certificate) (x509Cert *x509.Certificate, keyBytes []byte, certBytes []byte, err error) {
	fmt.Println(name)
	key, keyBytes, err := genKeyECDSA(name)
	template, err := x509Template()

	if err != nil {
		return nil, nil, nil, err
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth}

	//set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	//hardcode to localhost for hostname verification
	subject.CommonName = "localhost"

	template.Subject = subject

	x509Cert, certBytes, err = genCertificateECDSA(name, &template, signCert, &key.PublicKey, signKey)
	return x509Cert, keyBytes, certBytes, err
}

//generate an EC certificate appropriate for use by a TLS server
func GenClientCertificateECDSA(name string, signKey *ecdsa.PrivateKey, signCert *x509.Certificate) (x509Cert *x509.Certificate, keyBytes []byte, certBytes []byte, err error) {
	fmt.Println(name)
	key, keyBytes, err := genKeyECDSA(name)
	template, err := x509Template()

	if err != nil {
		return nil, nil, nil, err
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	//set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name

	template.Subject = subject

	x509Cert, certBytes, err = genCertificateECDSA(name, &template, signCert, &key.PublicKey, signKey)
	return x509Cert, keyBytes, certBytes, err
}

//generate an EC certificate signing(CA) key pair and output as
//PEM-encoded files
func GenCertificateAuthorityECDSA(name string) (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {

	key, _, err := genKeyECDSA(name)
	template, err := x509Template()

	if err != nil {
		return nil, nil, nil, err
	}

	//this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	//set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	x509Cert, certBytes, err := genCertificateECDSA(name, &template, &template, &key.PublicKey, key)

	if err != nil {
		return nil, nil, nil, err
	}
	return key, x509Cert, certBytes, nil
}

//generate an EC certificate appropriate for use by a TLS server
func genIntermediateCertificateAuthorityECDSA(name string, signKey *ecdsa.PrivateKey,
	signCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate, error) {

	fmt.Println(name)
	key, _, err := genKeyECDSA(name)
	template, err := x509Template()

	if err != nil {
		return nil, nil, err
	}

	//this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	//set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	x509Cert, _, err := genCertificateECDSA(name, &template, signCert, &key.PublicKey, signKey)

	if err != nil {
		return nil, nil, err
	}
	return key, x509Cert, nil
}


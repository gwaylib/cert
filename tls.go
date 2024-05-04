package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/gwaylib/errors"
)

func X509KeyPair(cert, key *pem.Block) (tls.Certificate, error) {
	c := tls.Certificate{
		Certificate: [][]byte{cert.Bytes},
	}
	privKey, err := x509.ParsePKCS1PrivateKey(key.Bytes)
	if err != nil {
		return c, errors.As(err)
	}
	c.PrivateKey = privKey
	return c, nil
}

//	subject := pkix.Name{
//		Organization:       []string{"lib10"},
//		OrganizationalUnit: []string{"wsnode"},
//		CommonName:         "auto-tls",
//	}
func GenX509Cert(subject pkix.Name, ipAddrs []net.IP) (cert, key *pem.Block, err error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)
	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		//KeyUsage:              x509.KeyUsageKeyEncipherment,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ipAddrs,
	}
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.As(err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &pk.PublicKey, pk)
	if err != nil {
		return nil, nil, errors.As(err)
	}
	return &pem.Block{Type: "CERTIFICATE", Bytes: derBytes},
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)},
		nil
}

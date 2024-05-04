package cert

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"

	"github.com/gwaylib/errors"
)

var (
	tlsConfig = &tls.Config{}
)

func AddTLSCert(cert tls.Certificate) error {
	if tlsConfig.Certificates == nil {
		tlsConfig.Certificates = make([]tls.Certificate, 0)
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, cert)

	// build name
	if tlsConfig.NameToCertificate == nil {
		tlsConfig.NameToCertificate = make(map[string]*tls.Certificate)
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return errors.As(err)
	}
	if len(x509Cert.Subject.CommonName) > 0 {
		tlsConfig.NameToCertificate[x509Cert.Subject.CommonName] = &cert
	}
	for _, san := range x509Cert.DNSNames {
		tlsConfig.NameToCertificate[san] = &cert
	}
	return nil
}

func GetTLSConfig() *tls.Config {
	return tlsConfig
}

func AddAutoCert(org, unit string) error {
	subject := pkix.Name{
		Organization:       []string{org},
		OrganizationalUnit: []string{unit},
		CommonName:         "auto-tls",
	}
	cert, key, err := GenX509Cert(subject, []net.IP{})
	if err != nil {
		return errors.As(err)
	}

	tlsCert, err := X509KeyPair(cert, key)
	if err != nil {
		return errors.As(err)
	}
	if err := AddTLSCert(tlsCert); err != nil {
		return errors.As(err)
	}
	return nil
}

func AddFileCert(keyFile, certFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return errors.As(err, keyFile, certFile)
	}
	if err := AddTLSCert(cert); err != nil {
		return errors.As(err, keyFile, certFile)
	}
	return nil
}

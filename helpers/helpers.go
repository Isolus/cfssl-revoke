// Package helpers implements utility functionality common to many
// CFSSL packages.
package helpers

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/Isolus/cfssl-revoke/crypto/pkcs7"
	cferr "github.com/Isolus/cfssl-revoke/errors"
	"github.com/Isolus/cfssl-revoke/log"
	"golang.org/x/crypto/pkcs12"
)

// ParseCertificatesPEM parses a sequence of PEM-encoded certificate and returns them,
// can handle PEM encoded PKCS #7 structures.
func ParseCertificatesPEM(certsPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err error
	certsPEM = bytes.TrimSpace(certsPEM)
	for len(certsPEM) > 0 {
		var cert []*x509.Certificate
		cert, certsPEM, err = ParseOneCertificateFromPEM(certsPEM)
		if err != nil {

			return nil, cferr.New(cferr.CertificateError, cferr.ParseFailed)
		} else if cert == nil {
			break
		}

		certs = append(certs, cert...)
	}
	if len(certsPEM) > 0 {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	}
	return certs, nil
}

// ParseCertificatesDER parses a DER encoding of a certificate object and possibly private key,
// either PKCS #7, PKCS #12, or raw x509.
func ParseCertificatesDER(certsDER []byte, password string) (certs []*x509.Certificate, key crypto.Signer, err error) {
	certsDER = bytes.TrimSpace(certsDER)
	pkcs7data, err := pkcs7.ParsePKCS7(certsDER)
	if err != nil {
		var pkcs12data interface{}
		certs = make([]*x509.Certificate, 1)
		pkcs12data, certs[0], err = pkcs12.Decode(certsDER, password)
		if err != nil {
			certs, err = x509.ParseCertificates(certsDER)
			if err != nil {
				return nil, nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
			}
		} else {
			key = pkcs12data.(crypto.Signer)
		}
	} else {
		if pkcs7data.ContentInfo != "SignedData" {
			return nil, nil, cferr.Wrap(cferr.CertificateError, cferr.DecodeFailed, errors.New("can only extract certificates from signed data content info"))
		}
		certs = pkcs7data.Content.SignedData.Certificates
	}
	if certs == nil {
		return nil, key, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	}
	return certs, key, nil
}

// ParseSelfSignedCertificatePEM parses a PEM-encoded certificate and check if it is self-signed.
func ParseSelfSignedCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.VerifyFailed, err)
	}
	return cert, nil
}

// ParseCertificatePEM parses and returns a PEM-encoded certificate,
// can handle PEM encoded PKCS #7 structures.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	certPEM = bytes.TrimSpace(certPEM)
	cert, rest, err := ParseOneCertificateFromPEM(certPEM)
	if err != nil {
		// Log the actual parsing error but throw a default parse error message.
		log.Debugf("Certificate parsing error: %v", err)
		return nil, cferr.New(cferr.CertificateError, cferr.ParseFailed)
	} else if cert == nil {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	} else if len(rest) > 0 {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, errors.New("the PEM file should contain only one object"))
	} else if len(cert) > 1 {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, errors.New("the PKCS7 object in the PEM file should contain only one certificate"))
	}
	return cert[0], nil
}

// ParseOneCertificateFromPEM attempts to parse one PEM encoded certificate object,
// either a raw x509 certificate or a PKCS #7 structure possibly containing
// multiple certificates, from the top of certsPEM, which itself may
// contain multiple PEM encoded certificate objects.
func ParseOneCertificateFromPEM(certsPEM []byte) ([]*x509.Certificate, []byte, error) {

	block, rest := pem.Decode(certsPEM)
	if block == nil {
		return nil, rest, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		pkcs7data, err := pkcs7.ParsePKCS7(block.Bytes)
		if err != nil {
			return nil, rest, err
		}
		if pkcs7data.ContentInfo != "SignedData" {
			return nil, rest, errors.New("only PKCS #7 Signed Data Content Info supported for certificate parsing")
		}
		certs := pkcs7data.Content.SignedData.Certificates
		if certs == nil {
			return nil, rest, errors.New("PKCS #7 structure contains no certificates")
		}
		return certs, rest, nil
	}
	var certs = []*x509.Certificate{cert}
	return certs, rest, nil
}

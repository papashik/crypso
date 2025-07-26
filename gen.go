package main

import (
	"crypso/x509"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"go.uber.org/zap"
)

var (
	defaultKeyAlgorithm = x509.MLDSA65.String()
)

const (
	privateKeyPEMType  = "PRIVATE KEY"
	certificatePEMType = "CERTIFICATE"

	bitSizeRSA = 2048
)

func isSupportedAlgorithm(algo string) bool {
	for _, a := range supportedAlgorithms {
		if a == algo {
			return true
		}
	}
	return false
}

type Generator struct {
	l *zap.Logger
}

func NewGenerator(l *zap.Logger) *Generator {
	return &Generator{l: l}
}

func (g *Generator) Key(privateFile, keyAlgorithm string) crypto.Signer {
	// if privateFile == "" {
	// 	privateFile = defaultPrivateKeyFilePath
	// 	g.l.Debug("Private key file is not specified, using default one", zap.String("path", privateFile))
	// }
	path := zap.String("path", privateFile)
	g.l.Debug("Checking if private key file exists", path)

	if _, err := os.Stat(privateFile); err == nil {
		g.l.Debug("Private key file exists, trying to unmarshal", path)
		keyBytes, err := os.ReadFile(privateFile)
		if err != nil {
			g.l.Fatal("Failed to open private key file for reading", path, zap.Error(err))
		}

		g.l.Debug("Opened private key file for reading", path)

		var p *pem.Block
		if p, _ = pem.Decode(keyBytes); p == nil {
			g.l.Warn("Failed to read PEM data from private key file", path)
			goto generate
		} else if p.Type != privateKeyPEMType {
			g.l.Fatal("Found invalid PEM block type", path, zap.String("type", p.Type),
				zap.String("expected_type", privateKeyPEMType))
		}

		key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil {
			g.l.Fatal("Failed to unmarshal private key", path, zap.Error(err))
		}

		algo := privateKeyAlgorithm(key)
		g.l.Info("Read private key from file", path, zap.String("algorithm", algo))

		g.l.Debug("Comparing request and certificate key algorithms")
		if keyAlgorithm == "" {
			g.l.Debug("Requested private key algorithm is empty, using found one", zap.String("algorithm", algo))
			keyAlgorithm = algo
		} else if !isSupportedAlgorithm(keyAlgorithm) {
			g.l.Debug("Unknown request key algorithm, using default one",
				zap.String("request_algorithm", keyAlgorithm), zap.String("default", defaultKeyAlgorithm))
			keyAlgorithm = defaultKeyAlgorithm
		}

		if keyAlgorithm == algo {
			g.l.Debug("Request and certificate private key algorithms are equal", zap.String("algorithm", algo))
			switch keyAlgorithm {
			case x509.MLDSA65.String():
				return key.(*mldsa65.PrivateKey)
			case x509.ECDSA.String():
				return key.(*ecdsa.PrivateKey)
			case x509.RSA.String():
				return key.(*rsa.PrivateKey)
			case x509.Ed25519.String():
				return key.(ed25519.PrivateKey)
			default:
				g.l.Error("Unreachable", zap.String("algorithm", keyAlgorithm))
			}
		}

		g.l.Warn("Private key algorithm differs, regenerating", path,
			zap.String("algorithm", algo), zap.String("request_algorithm", keyAlgorithm))

	} else if errors.Is(err, os.ErrNotExist) {
		g.l.Debug("Private key file does not exist, creating a new one", path)
	} else {
		g.l.Fatal("Failed to check private key file stat", path, zap.Error(err))
	}

generate:
	keyOut, err := os.OpenFile(privateFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		g.l.Fatal("Failed to open private key file for writing", path, zap.Error(err))
	}
	defer keyOut.Close()

	var (
		private   crypto.Signer
		privBytes []byte
	)
	switch keyAlgorithm {
	default:
		g.l.Warn("Unknown private key algorithm to generate, using default one",
			zap.String("algorithm", keyAlgorithm), zap.String("default", defaultKeyAlgorithm))
		keyAlgorithm = defaultKeyAlgorithm
		fallthrough
	case x509.MLDSA65.String():
		_, private, err = mldsa65.GenerateKey(rand.Reader)
	case x509.ECDSA.String():
		private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case x509.RSA.String():
		private, err = rsa.GenerateKey(rand.Reader, bitSizeRSA)
	case x509.Ed25519.String():
		_, private, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		g.l.Fatal("Failed to generate private key", zap.Error(err))
	}

	privBytes, err = x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		g.l.Fatal("Failed to marshal private key", zap.Error(err))
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: privateKeyPEMType, Bytes: privBytes}); err != nil {
		g.l.Fatal("Failed to write PEM data to private key file", zap.Error(err))
	}

	g.l.Info("Generated private key", path, zap.String("algorithm", keyAlgorithm))

	return private
}

type CertificateConfig struct {
	File string

	Organization string
	Start        time.Time
	Dur          time.Duration
	// If empty, localhost will be used
	Hosts []string
	// CA private key
	Private crypto.Signer

	IsCA bool

	// Must be empty in CA certificate
	PublicKey crypto.PublicKey
	Parent    *x509.Certificate
}

func (cfg *CertificateConfig) equalToCert(l *zap.Logger, cert *x509.Certificate) bool {
	path := zap.String("path", cfg.File)
	l.Debug("Comparing two certificates", path)
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != cfg.Organization {
		l.Debug("Organization differs", zap.String("request_organization", cfg.Organization))
		return false
	}

	if cert.NotBefore != cfg.Start || cert.NotAfter.Sub(cert.NotBefore) != cfg.Dur {
		l.Debug("Time differs", zap.Time("request_start", cfg.Start), zap.Duration("request_duration", cfg.Dur))
		return false
	}

	if len(cert.DNSNames)+len(cert.IPAddresses) != len(cfg.Hosts) {
		l.Debug("Hosts number differs", zap.Strings("request_hosts", cfg.Hosts))
		return false
	}
	mapCert := map[string]bool{}
	for _, n := range cert.DNSNames {
		mapCert[n] = true
	}

	for _, ip := range cert.IPAddresses {
		mapCert[ip.String()] = true
	}

	for _, c := range cfg.Hosts {
		if !mapCert[c] {
			l.Debug("No host name in certificate", zap.String("host", c))
			return false
		}
	}

	if cert.IsCA != cfg.IsCA {
		l.Debug("CA flag differs", zap.Bool("request_is_ca", cfg.IsCA))
		return false
	}

	pub := cert.PublicKey.(interface{ Equal(x crypto.PublicKey) bool })
	var (
		pub1   crypto.PublicKey
		parent *x509.Certificate
	)
	if cert.IsCA {
		pub1 = cfg.Private.Public()
		parent = cert
	} else {
		pub1 = cfg.PublicKey
		parent = cfg.Parent
	}
	if !pub.Equal(pub1) {
		l.Debug("Public key differs")
		return false
	}

	if err := cert.VerifyRoots(parent); err != nil {
		l.Debug("Failed to verify, using requested parent", zap.Error(err))
		return false
	}

	l.Debug("Certificate and request are equal")
	return true
}

func (g *Generator) Certificate(cfg CertificateConfig) *x509.Certificate {
	cert := tryToReadCertificate(g.l, cfg.File)
	if cert != nil && !cfg.equalToCert(g.l, cert) {
		g.l.Warn("Certificate exists, but differs from requested, regenerating")
	} else if cert != nil {
		return cert
	}

	certOut, err := os.Create(cfg.File)
	if err != nil {
		g.l.Fatal("Failed to open certificate file for writing", zap.Error(err), zap.String("path", cfg.File))
	}
	defer certOut.Close()

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate
	keyUsage := x509.KeyUsageDigitalSignature
	if publicKeyAlgorithm(cfg.PublicKey) == x509.RSA {
		// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
		// the context of TLS this KeyUsage is particular to RSA key exchange and
		// authentication.
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := x509.Certificate{
		//SignatureAlgorithm: x,
		Subject: pkix.Name{
			Organization: []string{cfg.Organization},
		},
		NotBefore: cfg.Start,
		NotAfter:  cfg.Start.Add(cfg.Dur),

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// if len(cfg.Hosts) == 0 {
	// 	cfg.Hosts = []string{"localhost"}
	// }

	for _, h := range cfg.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	var derBytes []byte

	if cfg.IsCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, cfg.Private.Public(), cfg.Private)
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, cfg.Parent, cfg.PublicKey, cfg.Private)
	}

	if err != nil {
		g.l.Fatal("Failed to create certificate", zap.Error(err), zap.Bool("is_ca", cfg.IsCA))
	}

	if err := pem.Encode(certOut, &pem.Block{Type: certificatePEMType, Bytes: derBytes}); err != nil {
		g.l.Fatal("Failed to write data to certificate file", zap.Error(err))
	}

	g.l.Info("Generated certificate", zap.String("path", cfg.File))

	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		g.l.Fatal("Failed to parse generated certificate", zap.Error(err))
	}
	return cert
}

func tryToReadCertificate(l *zap.Logger, file string) *x509.Certificate {
	path := zap.String("path", file)

	l.Debug("Checking if certificate file exists", path)

	if _, err := os.Stat(file); err == nil {
		l.Debug("Certificate file exists, trying to unmarshal", path)
		keyBytes, err := os.ReadFile(file)
		if err != nil {
			l.Fatal("Failed to open certificate file for reading", path, zap.Error(err))
		}

		l.Debug("Opened certificate file for reading", path)

		var p *pem.Block
		if p, _ = pem.Decode(keyBytes); p == nil {
			l.Warn("Failed to read PEM data from certificate file", path)
			return nil
		} else if p.Type != certificatePEMType {
			l.Fatal("Found invalid PEM block type", path, zap.String("type", p.Type),
				zap.String("expected_type", certificatePEMType))
		}

		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			l.Fatal("Failed to unmarshal certificate", path, zap.Error(err))
		}

		l.Info("Read certificate from file", path, zap.String("algorithm", cert.PublicKeyAlgorithm.String()))
		return cert

	} else if errors.Is(err, os.ErrNotExist) {
		l.Debug("Certificate file does not exist", path)
	} else {
		l.Fatal("Failed to check certificate file stat", path, zap.Error(err))
	}
	return nil
}

func privateKeyAlgorithm(key crypto.PrivateKey) string {
	switch key.(type) {
	case *mldsa65.PrivateKey:
		return x509.MLDSA65.String()
	case *ecdsa.PrivateKey:
		return x509.ECDSA.String()
	case *rsa.PrivateKey:
		return x509.RSA.String()
	case ed25519.PrivateKey:
		return x509.Ed25519.String()
	default:
		return "unknown"
	}
}

func publicKeyAlgorithm(key crypto.PublicKey) x509.PublicKeyAlgorithm {
	switch key.(type) {
	case *mldsa65.PublicKey:
		return x509.MLDSA65
	case *ecdsa.PublicKey:
		return x509.ECDSA
	case *rsa.PublicKey:
		return x509.RSA
	case ed25519.PublicKey:
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

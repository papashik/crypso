package main

import (
	"crypso/x509"
	"crypso/x509/pkix"
	"errors"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"go.uber.org/zap"
)

const (
	defaultPrivateKeyFilePath    = "key.pem"
	defaultCertificateFilePath   = "cert.pem"
	defaultCACertificateFilePath = "ca.pem"
	defaultKeyAlgorithm          = "mldsa65"
	privateKeyPEMType            = "PRIVATE KEY"
	certificatePEMType           = "CERTIFICATE"

	bitSizeRSA = 2048
)

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
			g.l.Fatal("Failed to read PEM data from private key file", path)
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
		if keyAlgorithm != "" && keyAlgorithm != algo {
			g.l.Fatal("Private key algorithm differs", path,
				zap.String("algorithm", algo), zap.String("expected_algorithm", keyAlgorithm))
		}
		return key.(crypto.Signer)

	} else if errors.Is(err, os.ErrNotExist) {
		g.l.Debug("Private key file does not exist, creating a new one", path)
	} else {
		g.l.Fatal("Failed to check private key file stat", path, zap.Error(err))
	}

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
	case "mldsa65":
		_, private, err = mldsa65.GenerateKey(rand.Reader)
	case "ecdsa":
		private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		private, err = rsa.GenerateKey(rand.Reader, bitSizeRSA)

	case "ed25519":
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

func (g *Generator) Certificate(cfg CertificateConfig) *x509.Certificate {
	if cfg.File == "" {
		cfg.File = defaultCertificateFilePath
		if cfg.IsCA {
			cfg.File = defaultCACertificateFilePath
		}
		g.l.Debug("Certificate file is not specified, using default one", zap.String("path", cfg.File))
	}

	if cert := tryToReadCertificate(g.l, cfg.File); cert != nil {
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
	if publicKeyAlgorithm(cfg.PublicKey) == "rsa" {
		// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
		// the context of TLS this KeyUsage is particular to RSA key exchange and
		// authentication.
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{cfg.Organization},
		},
		NotBefore: cfg.Start,
		NotAfter:  cfg.Start.Add(cfg.Dur),

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if len(cfg.Hosts) == 0 {
		cfg.Hosts = []string{"localhost"}
	}

	for _, h := range cfg.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	var derBytes []byte

	if cfg.IsCA {
		template.IsCA = true
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

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		g.l.Fatal("Failed to parse generated certificate", zap.Error(err))
	}
	return cert
}

type Verifier struct {
	l *zap.Logger
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
			l.Fatal("Failed to read PEM data from certificate file", path)
		} else if p.Type != certificatePEMType {
			l.Fatal("Found invalid PEM block type", path, zap.String("type", p.Type),
				zap.String("expected_type", certificatePEMType))
		}

		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			l.Fatal("Failed to unmarshal certificate", path, zap.Error(err))
		}

		algo := publicKeyAlgorithm(cert.PublicKeyAlgorithm)
		l.Info("Read certificate from file", path, zap.String("algorithm", algo))
		return cert

	} else if errors.Is(err, os.ErrNotExist) {
		l.Debug("Certificate file does not exist, creating a new one", path)
	} else {
		l.Fatal("Failed to check certificate file stat", path, zap.Error(err))
	}
	return nil
}

func privateKeyAlgorithm(key crypto.PrivateKey) string {
	switch key.(type) {
	case *mldsa65.PrivateKey:
		return "mldsa65"
	case *ecdsa.PrivateKey:
		return "ecdsa"
	case *rsa.PrivateKey:
		return "rsa"
	case ed25519.PrivateKey:
		return "ed25519"
	default:
		return "unknown"
	}
}

func publicKeyAlgorithm(key crypto.PublicKey) string {
	switch key.(type) {
	case *mldsa65.PublicKey:
		return "mldsa65"
	case *ecdsa.PublicKey:
		return "ecdsa"
	case *rsa.PublicKey:
		return "rsa"
	case ed25519.PublicKey:
		return "ed25519"
	default:
		return "unknown"
	}
}

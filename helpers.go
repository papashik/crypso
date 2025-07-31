package main

import (
	"reflect"

	"github.com/papashik/crypso/x509"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"go.uber.org/zap"
)

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
		return "Unknown: " + reflect.TypeOf(key).Name()
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

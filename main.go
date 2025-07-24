package main

import (
	"crypso/x509"

	"crypto"
	"fmt"
	"os"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
)

var (
	flagVerbose int

	flagPrivateKeyFile string
	flagKeyAlgorithm   string
	flagCertFile       string
	flagCertName       string
	flagCertStart      time.Time
	flagCertDuration   time.Duration
	flagCertHosts      string

	flagCAPrivateKeyFile string
	flagCAKeyAlgorithm   string
	flagCACertFile       string
	flagCACertName       string
	flagCACertStart      time.Time
	flagCACertDuration   time.Duration

	mode Mode

	timeFormats = []string{"Jan 1 15:04:05 2011"}
)

type Mode = string

const (
	modeGen    Mode = "gen"
	modeVerify Mode = "verify"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of crypso:\n")
		fmt.Fprintf(os.Stderr, "  crypso [MODE] [flags]\n")
		fmt.Fprintf(os.Stderr, "  where MODE is one of: %s, %s\n", modeGen, modeVerify)
		flag.PrintDefaults()
	}
	flag.CountVarP(&flagVerbose, "verbose", "v", "level of logging(-v, -vv or -vvv)")

	flag.StringVar(&flagPrivateKeyFile, "private", "", "private key filename (will be used or generated)")
	flag.StringVar(&flagKeyAlgorithm, "algorithm", "",
		`private key algorithm to generate, must be one of: 'mldsa65', 'ecdsa' (P-256), 'rsa', 'ed25519'`)
	flag.StringVar(&flagCertFile, "cert", "", "certificate filename")
	flag.StringVar(&flagCertName, "name", "", "certificate organization name")
	flag.TimeVar(&flagCertStart, "start", time.Time{}, timeFormats, "creation date formatted as one of "+strings.Join(timeFormats, ", "))
	flag.DurationVar(&flagCertDuration, "duration", 0, "CA certificate duration")
	flag.StringVar(&flagCertHosts, "hosts", "", "comma-separated hostnames and IPs to generate a certificate for")

	flag.StringVar(&flagCAPrivateKeyFile, "ca-private", "", "CA private key filename (will be used or generated)")
	flag.StringVar(&flagCAKeyAlgorithm, "ca-algorithm", "",
		`CA private key algorithm to generate, must be one of: 'mldsa65', 'ecdsa' (P-256), 'rsa', 'ed25519'`)
	flag.StringVar(&flagCACertFile, "ca-cert", "", "CA certificate filename")
	flag.StringVar(&flagCACertName, "ca-name", "", "CA certificate organization name")
	flag.TimeVar(&flagCACertStart, "ca-start", time.Time{}, timeFormats, "creation date formatted as one of "+strings.Join(timeFormats, ", "))
	flag.DurationVar(&flagCACertDuration, "ca-duration", 0, "CA certificate duration")

	flag.Parse()

	l := newLogger(flagVerbose)

	mode = Mode(flag.Arg(0))
	l.Debug("Starting", zap.String("mode", mode))

	switch mode {
	case modeGen:
		gen := NewGenerator(l)
		var key crypto.Signer
		if flagPrivateKeyFile == "" && flagCAPrivateKeyFile == "" {
			l.Fatal("Specify at least one of: private key file, CA private key file")
		}

		if flagPrivateKeyFile != "" {
			key = gen.Key(flagPrivateKeyFile, flagKeyAlgorithm)
		}
		if flagCAPrivateKeyFile != "" {
			caKey := gen.Key(flagCAPrivateKeyFile, flagCAKeyAlgorithm)
			if flagCACertFile != "" {
				caCert := gen.Certificate(CertificateConfig{
					File:         flagCACertFile,
					Organization: flagCACertName,
					Start:        flagCACertStart,
					Dur:          flagCACertDuration,
					Private:      caKey,
					IsCA:         true,
				})
				if flagCertFile != "" {
					if flagPrivateKeyFile == "" {
						l.Fatal("Certificate private key file name is empty")
					}
					gen.Certificate(CertificateConfig{
						File:         flagCertFile,
						Organization: flagCertName,
						Start:        flagCertStart,
						Dur:          flagCertDuration,
						Private:      caKey,
						IsCA:         false,
						PublicKey:    key.Public(),
						Parent:       caCert,
					})
				}
			}
		}
	case modeVerify:
		caFile := flag.Arg(1)
		certFile := flag.Arg(2)
		var ca, cert *x509.Certificate
		ca = tryToReadCertificate(l, caFile)
		cert = tryToReadCertificate(l, certFile)
		pool := x509.CertPool{}
		pool.AddCert(ca)
		//pool.AddCert(cert)
		_, err := cert.Verify(x509.VerifyOptions{Roots: &pool})
		if err != nil {
			l.Fatal("Failed to verify certificate", zap.Error(err))
		}
		//fmt.Println(x.UnknownPublicKeyAlgorithm)
	default:
		l.Fatal("Working mode is invalid")
	}

	l.Debug("Exiting")
}

func newLogger(verbose int) *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	switch verbose {
	case 0:
		cfg.Level.SetLevel(zap.ErrorLevel)
	case 1:
		cfg.Level.SetLevel(zap.WarnLevel)
	case 2:
		cfg.Level.SetLevel(zap.InfoLevel)
	default:
		cfg.Level.SetLevel(zap.DebugLevel)
	}
	cfg.Sampling = nil
	cfg.DisableCaller = true
	cfg.DisableStacktrace = true
	cfg.EncoderConfig.TimeKey = ""

	return zap.Must(cfg.Build())
}

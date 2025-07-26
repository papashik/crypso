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
	"go.uber.org/zap/zapcore"
)

var (
	flagVerbose          int
	flagSuppressWarnings bool
	flagJSONLogger       bool

	flagPrivateKeyFile string
	flagKeyAlgorithm   string
	flagCertFile       string
	flagCertName       string
	flagCertStart      time.Time
	flagCertDuration   time.Duration
	flagCertHosts      []string

	flagCAPrivateKeyFile string
	flagCAKeyAlgorithm   string
	flagCACertFile       string
	flagCACertName       string
	flagCACertStart      time.Time
	flagCACertDuration   time.Duration

	mode Mode

	timeFormats         = []string{time.DateOnly}
	supportedAlgorithms = []string{
		x509.MLDSA65.String(),
		x509.ECDSA.String(),
		x509.RSA.String(),
		x509.Ed25519.String(),
	}
)

type Mode = string

const (
	modeGen    Mode = "gen"
	modeVerify Mode = "verify"
)

func main() {
	f := flag.NewFlagSet("", flag.ExitOnError)
	f.SortFlags = false
	f.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of crypso:\n")
		fmt.Fprintf(os.Stderr, "  crypso MODE {flag}\n")
		fmt.Fprintf(os.Stderr, "  where MODE is one of:\n")
		fmt.Fprintf(os.Stderr, "    %s\n", modeGen)
		fmt.Fprintf(os.Stderr, "    %s PATH {CA_PATH}\n", modeVerify)
		fmt.Fprintf(os.Stderr, "Flags:\n")
		f.PrintDefaults()
	}
	f.CountVarP(&flagVerbose, "verbose", "v", "use verbose logging (-v or -vv)")
	f.BoolVar(&flagSuppressWarnings, "suppress-warnings", false, "suppress warning-level messages")
	f.BoolVarP(&flagJSONLogger, "json", "j", false, "output logs in JSON format")

	f.StringVar(&flagPrivateKeyFile, "private", "", "private key filename (will be used or generated)")
	f.StringVar(&flagKeyAlgorithm, "algorithm", "",
		`private key algorithm to generate, must be one of: `+strings.Join(supportedAlgorithms, ", "))
	f.StringVar(&flagCertFile, "cert", "", "certificate filename")
	f.StringVar(&flagCertName, "name", "", "certificate organization name")
	f.TimeVar(&flagCertStart, "start", time.Time{}, timeFormats, "creation date formatted as one of "+strings.Join(timeFormats, ", "))
	f.DurationVar(&flagCertDuration, "duration", 365*24*time.Hour, "certificate duration")
	f.StringSliceVar(&flagCertHosts, "hosts", []string{}, "comma-separated hostnames and IPs to generate a certificate for")

	f.StringVar(&flagCAPrivateKeyFile, "ca-private", "", "CA private key filename (will be used or generated)")
	f.StringVar(&flagCAKeyAlgorithm, "ca-algorithm", "",
		`CA private key algorithm to generate, must be one of: `+strings.Join(supportedAlgorithms, ", "))
	f.StringVar(&flagCACertFile, "ca-cert", "", "CA certificate filename")
	f.StringVar(&flagCACertName, "ca-name", "", "CA certificate organization name")
	f.TimeVar(&flagCACertStart, "ca-start", time.Time{}, timeFormats, "creation date formatted as one of "+strings.Join(timeFormats, ", "))
	f.DurationVar(&flagCACertDuration, "ca-duration", 10*365*24*time.Hour, "CA certificate duration")

	f.Parse(os.Args[1:])

	l := newLogger(flagVerbose, flagSuppressWarnings, flagJSONLogger)

	mode = Mode(f.Arg(0))
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
						Hosts:        flagCertHosts,
						Private:      caKey,
						IsCA:         false,
						PublicKey:    key.Public(),
						Parent:       caCert,
					})
				}
			}
		}
	case modeVerify:
		pool := x509.NewCertPool()
		certFile := f.Arg(1)
		cert := tryToReadCertificate(l, certFile)
		if cert == nil {
			l.Fatal("Failed to read verifying certificate", zap.String("path", certFile))
		}
		if f.NArg() > 2 {
			caFiles := f.Args()[2:]
			for _, c := range caFiles {
				ca := tryToReadCertificate(l, c)
				if ca == nil {
					l.Fatal("Failed to read CA certificate", zap.String("path", c))
				}
				pool.AddCert(ca)
			}
		}

		l.Debug("Trying to verify")
		_, err := cert.Verify(x509.VerifyOptions{Roots: pool})
		if err != nil {
			l.Fatal("Failed to verify certificate", zap.Error(err))
		}

		l.Info("Successfully verified")
	default:
		l.Fatal("Working mode is invalid")
	}

	l.Debug("Exiting")
}

func newLogger(verbose int, suppressWarnings, inJSON bool) *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	cfg.DisableCaller = true
	cfg.EncoderConfig.TimeKey = ""
	if inJSON {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}
	cfg.DisableStacktrace = true
	switch verbose {
	case 0:
		cfg.Level.SetLevel(zap.WarnLevel)
	case 1:
		cfg.Level.SetLevel(zap.InfoLevel)
	default:
		cfg.Level.SetLevel(zap.DebugLevel)
	}

	if suppressWarnings {
		cfg.Level.SetLevel(zap.ErrorLevel)
	}

	//cfg.Sampling = nil
	//
	//cfg.DisableStacktrace = true

	return zap.Must(cfg.Build())
}

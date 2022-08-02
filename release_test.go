package cacenter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	sm2X509 "github.com/tjfoc/gmsm/x509"
	"math/big"
	"testing"
	"time"
)

func BenchmarkRsaRelease(b *testing.B) {
	a := assert.New(b)

	parser := new(Parser)
	p := new(Producer)
	rootSubject := pkix.Name{
		CommonName:   "测试CA",
		Organization: []string{"测试CA"},
		Country:      []string{"zh"},
	}
	rootCertProducer, rootPriKeyPem, err := p.Rsa(2048)
	if !a.NoError(err) {
		return
	}
	rootCertBytes, err := rootCertProducer.
		WithSubject(rootSubject).
		WithIssuer(rootSubject).
		WithCaTemplate().
		ToCertBytes()
	if !a.NoError(err) {
		return
	}

	rootCert, err := parser.ParseByCertBytes(rootCertBytes)
	if !a.NoError(err) {
		return
	}

	rootPriKey, err := parser.ParseByRsaPriKeyPem(rootPriKeyPem)
	if !a.NoError(err) {
		return
	}

	tlsSubjectInfo := pkix.Name{
		CommonName:   "测试服务器证书",
		Organization: []string{"bypt"},
	}
	tlsServerCertProducer, _, err := p.Rsa(2048)
	if !a.NoError(err) {
		return
	}

	b.Run("create_rsa_2048_cert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = tlsServerCertProducer.
				WithSubject(tlsSubjectInfo).
				WithIssuer(rootSubject).
				WithParent(rootCert, rootPriKey).
				WithTLSServer(TLSAddrWithDNSName("apps.byzk.cn")).
				ToCertPem()
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("create_rsa_2048_key", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Rsa(2048)
		}
	})

}

func BenchmarkSm2Release(b *testing.B) {
	a := assert.New(b)

	parser := new(Parser)
	p := new(Producer)
	rootSubject := pkix.Name{
		CommonName:   "测试CA",
		Organization: []string{"测试CA"},
		Country:      []string{"zh"},
	}
	rootCertProducer, rootPriKeyPem, err := p.Sm2()
	if !a.NoError(err) {
		return
	}
	rootCertBytes, err := rootCertProducer.
		WithSubject(rootSubject).
		WithIssuer(rootSubject).
		WithCaTemplate().
		ToCertBytes()
	if !a.NoError(err) {
		return
	}

	rootCert, err := parser.ParseBySm2CertBytes(rootCertBytes)
	if !a.NoError(err) {
		return
	}

	rootPriKey, err := parser.ParseBySm2PriKeyPem(rootPriKeyPem)
	if !a.NoError(err) {
		return
	}

	tlsSubjectInfo := pkix.Name{
		CommonName:   "测试服务器证书",
		Organization: []string{"bypt"},
	}
	tlsServerCertProducer, _, err := p.Sm2()
	if !a.NoError(err) {
		return
	}

	b.Run("create_sm2_cert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tlsServerCertProducer, _, err = p.Sm2()
			if !a.NoError(err) {
				return
			}
			_, err = tlsServerCertProducer.
				WithSubject(tlsSubjectInfo).
				WithIssuer(rootSubject).
				WithParent(rootCert, rootPriKey).
				WithTLSServer(TLSAddrWithDNSName("apps.byzk.cn")).
				ToCertPem()
			if err != nil {
				b.Error(err)
			}

		}
	})

	b.Run("create_sm2_key", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Sm2()
		}
	})

}

func TestRsaCertRelease(t *testing.T) {
	a := assert.New(t)

	certNo := time.Now().UnixNano()

	producer := new(Producer)

	rsaProducer, rootPriKeyPem, err := producer.Rsa(2048)
	if !a.NoError(err) {
		return
	}

	subjectInfo := pkix.Name{
		CommonName:   "测试",
		Organization: []string{"测试2"},
	}
	rootCertBytes, err := rsaProducer.SettingCertInfo(func(parentCert, templateCert *x509.Certificate) {
		templateCert.SerialNumber = big.NewInt(certNo)
	}).WithSubject(subjectInfo).WithIssuer(subjectInfo).WithCaTemplate().ToCertBytes()
	if !a.NoError(err) {
		return
	}

	parser := new(Parser)
	certificate, err := parser.ParseByCertBytes(rootCertBytes)
	if !a.NoError(err) {
		return
	}

	if !a.Equal(certificate.SerialNumber.Int64(), certNo) {
		return
	}

	rootPriKey, err := parser.ParseByRsaPriKeyPem(rootPriKeyPem)
	if !a.NoError(err) {
		return
	}

	tlsServerProducer, _, err := producer.Rsa(2048)
	if !a.NoError(err) {
		return
	}

	tlsSubjectInfo := pkix.Name{
		CommonName:   "测试TLS Server",
		Organization: []string{"test"},
	}

	tlsServerCertBytes, err := tlsServerProducer.
		WithSubject(tlsSubjectInfo).
		WithIssuer(subjectInfo).
		WithParent(certificate, rootPriKey).
		WithTLSServer(TLSAddrWithDNSName("apps.byzk.cn")).
		ToCertBytes()

	tlsServerCert, err := parser.ParseByCertBytes(tlsServerCertBytes)
	if !a.NoError(err) {
		return
	}

	if err = tlsServerCert.CheckSignatureFrom(certificate); !a.NoError(err) {
		return
	}

	if err = tlsServerCert.CheckSignatureFrom(tlsServerCert); !a.Error(err) {
		return
	}

}

func TestSm2CertRelease(t *testing.T) {
	a := assert.New(t)

	certNo := time.Now().UnixNano()

	producer := new(Producer)

	sm2Producer, rootPriKeyPem, err := producer.Sm2()
	if !a.NoError(err) {
		return
	}

	subjectInfo := pkix.Name{
		CommonName:   "测试",
		Organization: []string{"测试2"},
	}
	rootCertBytes, err := sm2Producer.SettingCertInfo(func(parentCert, templateCert *sm2X509.Certificate) {
		templateCert.SerialNumber = big.NewInt(certNo)
	}).WithSubject(subjectInfo).WithIssuer(subjectInfo).WithCaTemplate().
		ToCertBytes()
	if !a.NoError(err) {
		return
	}

	parser := new(Parser)
	certificate, err := parser.ParseBySm2CertBytes(rootCertBytes)
	if !a.NoError(err) {
		return
	}

	if !a.Equal(certificate.SerialNumber.Int64(), certNo) {
		return
	}

	rootPriKey, err := parser.ParseBySm2PriKeyPem(rootPriKeyPem)
	if !a.NoError(err) {
		return
	}

	tlsServerProducer, _, err := producer.Sm2()
	if !a.NoError(err) {
		return
	}

	tlsSubjectInfo := pkix.Name{
		CommonName:   "测试TLS Server",
		Organization: []string{"test"},
	}

	tlsServerCertBytes, err := tlsServerProducer.
		WithSubject(tlsSubjectInfo).
		WithIssuer(subjectInfo).
		WithParent(certificate, rootPriKey).
		WithTLSServer(TLSAddrWithDNSName("apps.byzk.cn")).
		ToCertBytes()

	tlsServerCert, err := parser.ParseBySm2CertBytes(tlsServerCertBytes)
	if !a.NoError(err) {
		return
	}

	if err = tlsServerCert.CheckSignatureFrom(certificate); !a.NoError(err) {
		return
	}

	if err = tlsServerCert.CheckSignatureFrom(tlsServerCert); !a.Error(err) {
		return
	}

}

func BenchmarkCreateCertificate(b *testing.B) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"example.com"},
	}
	tests := []struct {
		name string
		gen  func() crypto.Signer
	}{
		{
			name: "RSA 2048",
			gen: func() crypto.Signer {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					b.Fatalf("failed to generate test key: %s", err)
				}
				return k
			},
		},
		{
			name: "ECDSA P256",
			gen: func() crypto.Signer {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					b.Fatalf("failed to generate test key: %s", err)
				}
				return k
			},
		},
	}

	for _, tc := range tests {
		k := tc.gen()
		b.ResetTimer()
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
				if err != nil {
					b.Fatalf("failed to create certificate: %s", err)
				}
			}
		})
	}
}

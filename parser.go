package cacenter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	sm2X509 "github.com/tjfoc/gmsm/x509"
)

type Parser struct {
}

func (c *Parser) ParseByCertBytes(certData []byte) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(certData)
	if err == nil {
		return certificate, nil
	}

	certificate, err = sm2X509.ParseSm2CertifateToX509(certData)
	if err != nil {
		return nil, fmt.Errorf("证书格式解析失败: 未知的证书格式")
	}

	return certificate, nil
}

func (c *Parser) ParseByCertPemBytes(certData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("非PEM格式的证书信息")
	}
	return c.ParseByCertBytes(block.Bytes)
}

func (c *Parser) ParseByCertPem(certData string) (*x509.Certificate, error) {
	return c.ParseByCertPemBytes([]byte(certData))
}

func (c *Parser) ParseBySm2CertBytes(certData []byte) (*sm2X509.Certificate, error) {
	certificate, err := sm2X509.ParseCertificate(certData)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func (c *Parser) ParseBySm2CertPemBytes(certData []byte) (*sm2X509.Certificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("非PEM格式的证书信息")
	}
	return c.ParseBySm2CertBytes(block.Bytes)
}

func (c *Parser) ParseBySm2CertPem(certData string) (*sm2X509.Certificate, error) {
	return c.ParseBySm2CertPemBytes([]byte(certData))
}

func (c *Parser) ParseByRsaPriKeyPem(priKey string) (*rsa.PrivateKey, error) {
	return c.ParseByRsaPriKeyPemBytes([]byte(priKey))
}

func (c *Parser) ParseByRsaPriKeyPemBytes(priKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, fmt.Errorf("非PEM格式的RSA私钥")
	}
	return c.ParseByRsaPriKeyBytes(block.Bytes)
}

func (c *Parser) ParseByRsaPriKeyBytes(priKey []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(priKey)
}

func (c *Parser) ParseBySm2PriKeyPem(priKey string) (*sm2.PrivateKey, error) {
	return c.ParseBySm2PriKeyPemBytes([]byte(priKey))
}

func (c *Parser) ParseBySm2PriKeyPemBytes(priKey []byte) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return nil, fmt.Errorf("非PEM格式的RSA私钥")
	}
	return c.ParseBySm2PriKeyBytes(block.Bytes)
}

func (c *Parser) ParseBySm2PriKeyBytes(priKey []byte) (*sm2.PrivateKey, error) {
	return sm2X509.ParsePKCS8PrivateKey(priKey, nil)
}

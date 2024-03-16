package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

var initonce sync.Once
var tc26512a *elliptic.CurveParams
var tc26512b *elliptic.CurveParams

func initTC26512A() {
	tc26512a = new(elliptic.CurveParams)
	tc26512a.P, _ = new(big.Int).SetString("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", 16)
	tc26512a.N, _ = new(big.Int).SetString("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", 16)
	tc26512a.B, _ = new(big.Int).SetString("00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", 16)
	tc26512a.Gx, _ = new(big.Int).SetString("03", 16)
	tc26512a.Gy, _ = new(big.Int).SetString("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4", 16)
	tc26512a.BitSize = 512
}

func TC26512A() elliptic.Curve {
	initonce.Do(initTC26512A)
	return tc26512a
}

func initTC26512B() {
	tc26512b = new(elliptic.CurveParams)
	tc26512b.P, _ = new(big.Int).SetString("008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F", 16)
	tc26512b.N, _ = new(big.Int).SetString("00800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD", 16)
	tc26512b.B, _ = new(big.Int).SetString("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116", 16)
	tc26512b.Gx, _ = new(big.Int).SetString("02", 16)
	tc26512b.Gy, _ = new(big.Int).SetString("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD", 16)
	tc26512b.BitSize = 512
}

func TC26512B() elliptic.Curve {
	initonce.Do(initTC26512B)
	return tc26512b
}

var (
	//oidNamedCurveP224     = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	//oidNamedCurveP256     = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	//oidNamedCurveP384     = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	//oidNamedCurveP521     = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveTC26512A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1} // FIX: вставил для 256, нужно для 512
	oidNamedCurveTC26512B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case TC26512A():
		return oidNamedCurveTC26512A, true
	case TC26512B():
		return oidNamedCurveTC26512B, true
	}

	return nil, false
}

func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	oid, ok := oidFromNamedCurve(key.Curve)
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	return marshalECPrivateKeyWithOID(key, oid)
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func marshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("invalid elliptic key public key")
	}
	privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

func generateTC26Key(filename string) (key *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(TC26512A(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate TC 26 GOST R 34.10-2012 key: %s\n", err)
	}

	keyDer, err := MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("Failed to serialize ECDSA key: %s\n", err)
	}

	keyBlock := pem.Block{
		Type:  "TC 26 GOST R 34.10-2012 PRIVATE KEY",
		Bytes: keyDer,
	}

	keyFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to open ec_key.pem for writing: %s", err)
	}

	defer func() {
		err = keyFile.Close()
		if err != nil {
			log.Fatalln(err)
		}
	}()

	if err = pem.Encode(keyFile, &keyBlock); err != nil {
		log.Fatalf("Failed to encode pem block: %s", err)
	}

	return
}

func generateCert(pub, priv any, filename string) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Docker, Inc."},
		},
		NotBefore: time.Now().Add(-time.Hour * 24 * 365),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
	}
	certDer, err := x509.CreateCertificate(
		rand.Reader, &template, &template, pub, priv,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s\n", err)
	}

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	certFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to open '%s' for writing: %s", filename, err)
	}
	defer func() {
		err = certFile.Close()
		if err != nil {
			log.Fatalln(err)
		}
	}()

	err = pem.Encode(certFile, &certBlock)
	if err != nil {
		log.Fatalln(err)
	}
}


// Learning Go and the its TLS certificate internals
// No license yet

// Golang version: https://golang.org/src/crypto/tls/generate_cert.go

package tlsdump

import (
  "crypto/x509"
  "crypto/x509/pkix"
  "crypto/rand"
  "crypto/rsa"
  "crypto/elliptic"
  "crypto/ecdsa"
  "time"
  "errors"
  "math/big"
  "strings"
  "encoding/pem"
  "io/ioutil"
  "fmt"
)

const (

  // The valid constants are https://golang.org/pkg/crypto/x509/#KeyUsage, I am adding everything except the last two
  // More info: http://www.ibm.com/support/knowledgecenter/SSKTMJ_9.0.1/admin/conf_keyusageextensionsandextendedkeyusage_r.html
  // Practically we only need a few
  RootCAKeyUsage = x509.KeyUsageDigitalSignature |
    x509.KeyUsageContentCommitment |
    x509.KeyUsageKeyEncipherment |
    x509.KeyUsageDataEncipherment |
    x509.KeyUsageKeyAgreement |
    x509.KeyUsageCertSign |
    x509.KeyUsageCRLSign

  // leaf certs do not need to sign certificates and CRLS (e.g. cert revocation information)
  LeafCertKeyUsage = x509.KeyUsageDigitalSignature |
    x509.KeyUsageContentCommitment |
    x509.KeyUsageKeyEncipherment |
    x509.KeyUsageDataEncipherment |
    x509.KeyUsageKeyAgreement

  // CA validity in years
  CAValidity = 5

  // Leaf validity in years
  LeafValidity = 1
)

// GenerateKeypair create a pair of public/private keys for use in a certificate.
// Valid choices for algo are "RSA" and "ECDSA" (case-insensitive).
// If ECDSA is chosen then ecCurve will contain the curve, valid values are P224, P256, P384 and P521 (case-insensitive).
// Returns an empty interface containing the keypair.
func generateKeyPair(algo string, ecCurve string) (privateKey interface{}, publicKey interface{}, err error) {

  // Make them case-insensitive
  switch strings.ToUpper(algo) {
  // If RSA, generate a pair of RSA keys
  case "RSA":
    // rsa.GenerateKey(): https://golang.org/pkg/crypto/rsa/#GenerateKey
    // Return value is of type *rsa.PrivateKey
    privateKey, err = rsa.GenerateKey(rand.Reader, 2048) // by default create a 2048 bit key

  // If ECDSA, use a provided curve
  case "ECDSA":
    // First check if ecCurve is provided
    if ecCurve == "" {
      return nil, nil, errors.New("ECDSA needs a curve")
    }
    // Then generate the key based on the curve
    // Curves: https://golang.org/pkg/crypto/elliptic/#Curve
    // ecdsa.GenerateKey(): https://golang.org/pkg/crypto/ecdsa/#GenerateKey
    // Return value is of type *ecdsa.PrivateKey
    switch strings.ToUpper(ecCurve) {
    case "P224":
      privateKey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
    case "P256":
      privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    case "P384":
    	privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    case "P521":
    	privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

    // If the curve is invalid
    default:
      return nil, nil, errors.New("Unrecognized curve, valid values are P224, P256, P384 and P521")
    }

  // If neither RSA nor ECDSA return an error
  default:
    return nil, nil, errors.New("Unrecognized algorithm, valid options are RSA and ECDSA")
  }

  // If we get here, then input parameters have been valid
  // Check if key generation has been successful by checking err
  if err != nil {
    return nil, nil, err
  }

  // Exporting the public key (needed later)
  switch tempPrivKey:= privateKey.(type) {
  case *rsa.PrivateKey:
    publicKey = &tempPrivKey.PublicKey
  case *ecdsa.PrivateKey:
    publicKey = &tempPrivKey.PublicKey
  }

  return privateKey, publicKey, err // or just return
}

// GenerateCA creates a root certificate authority using the provided information.
// Returns the a self-signed root CA, private key and error if any.
func GenerateCA(commonName string,
  serialNumber int64,
  countryCode string,
  organizationalUnit string,
  algo string,
  ecCurve string) (rootCADER []byte, rootPrivateKeyDER []byte, err error) {

  notBefore := time.Now().UTC()
  notAfter := notBefore.AddDate(CAValidity, 0, 0) // (years, months. days)

  // Hashing algorithm should match the private key type that signs the certificate.
  // In this case we are self-signing so the key generation algorithm and signature hashing algorithm are both of the same type
  hashingAlgorithm := x509.SHA256WithRSA
  switch strings.ToUpper(algo) {
  case "RSA":
    // pass
  case "ECDSA":
    hashingAlgorithm = x509.ECDSAWithSHA256
  default:
    return nil, nil, errors.New("Unrecognized algorithm, valid options are RSA and ECDSA")
  }

  // https://golang.org/pkg/crypto/x509/#Certificate
  myCACertTemplate := x509.Certificate{

    // https://golang.org/pkg/crypto/x509/pkix/#Name
    Subject: pkix.Name{
      CommonName: commonName,
      Country: []string{countryCode},
      Organization: []string{organizationalUnit},
    },

    NotBefore: notBefore,
    NotAfter: notAfter,
    SerialNumber: big.NewInt(serialNumber), // returns *big.Int
    KeyUsage: RootCAKeyUsage,

    // For CAs we at least want []x509.ExtKeyUsage{x509.ExtKeyUsageAny | x509.KeyUsageCertSign}
    // More info: https://golang.org/pkg/crypto/x509/#ExtKeyUsage
    ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},  // this should work
    BasicConstraintsValid: true,
    IsCA: true,
    MaxPathLen: 3,  // 1 is enough for our purpose
    SignatureAlgorithm: hashingAlgorithm, // other options are at https://golang.org/pkg/crypto/x509/#SignatureAlgorithm
  }

  privKey, pubKey, err := generateKeyPair(algo, ecCurve)
  if err != nil {
    return nil, nil, err
  }

  // https://golang.org/pkg/crypto/x509/#CreateCertificate
  // Both the signee and singer are the same template because rootCAs are always self-signed
  rootCADER, err = x509.CreateCertificate(rand.Reader, &myCACertTemplate, &myCACertTemplate, pubKey, privKey)
  if err != nil {
    return nil, nil, err
  }

  rootPrivateKeyDER, err = MarshalPrivateKey(privKey)

  return rootCADER, rootPrivateKeyDER, err
}

// GenerateAndSignLeafCert creates and signs a leaf certificate.
// Returns signed leaf cert and private key both in DER format.
func GenerateAndSignLeafCert(commonName string,
  serialNumber int64,
  countryCode string,
  organizationalUnit string,
  algo string,
  ecCurve string,
  rootCADER []byte,
  rootPrivateKeyDER []byte) (leafCertDER []byte, leafCertPrivateKeyDER []byte, err error) {

  notBefore := time.Now().UTC()
  notAfter := notBefore.AddDate(LeafValidity, 0, 0) // (years, months, days)

  // Check inputs before doing things (zomg timing attacks, someone call the cryptographers /s)

  // https://golang.org/pkg/crypto/x509/#ParseCertificate
  rootCA, err := x509.ParseCertificate(rootCADER)
  if err != nil {
    return nil, nil, err
  }

  // Now we need to parse the private key
  // First we need to discover the private key algorithm (RSA vs ECDSA)
  // The algorithm is the same as rootCA.PublicKeyAlgorithm
  // https://golang.org/pkg/crypto/x509/#PublicKeyAlgorithm

  // We also need to match the signature hashing algorithm with private key of rootCA
  // Both should either be RSA or ECDSA
  // We will start with RSA and change it to ECDSA if we need to
  hashingAlgorithm := x509.SHA256WithRSA

  var rootCAPrivateKey interface{}

  rootCAPrivateKey, rootCAKeyAlgorithm, err := ParsePrivateKey(rootPrivateKeyDER)
  if err != nil {
    return nil, nil, errors.New("Could not parse CA private key")
  }

  switch rootCAKeyAlgorithm {
  case "EC":
    hashingAlgorithm = x509.ECDSAWithSHA256
  // Not really needed
  case "RSA":
    hashingAlgorithm = x509.SHA256WithRSA
  default:
    return nil, nil, errors.New("Root CA private key algorithm is neither RSA nor ECDSA")
  }

  leafCertTemplate := x509.Certificate{

    Subject: pkix.Name{
      CommonName: commonName,
      Country: []string{countryCode},
      Organization: []string{organizationalUnit},
    },

    NotBefore: notBefore,
    NotAfter: notAfter,
    SerialNumber: big.NewInt(serialNumber),
    KeyUsage: RootCAKeyUsage,

    // For CAs we at least want []x509.ExtKeyUsage{x509.ExtKeyUsageAny | x509.KeyUsageCertSign}
    // More info: https://golang.org/pkg/crypto/x509/#ExtKeyUsage
    ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},  // this should work
    BasicConstraintsValid: false, // not a root CA

    SignatureAlgorithm: hashingAlgorithm, // other options are at https://golang.org/pkg/crypto/x509/#SignatureAlgorithm
  }

  privKey, pubKey, err := generateKeyPair(algo, ecCurve)
  if err != nil {
    return nil, nil, err
  }

  // https://golang.org/pkg/crypto/x509/#CreateCertificate
  // First template is the cert being signed and the second is signer
  // Public key belongs to singee and private key belongs to signer
  leafCertDER, err = x509.CreateCertificate(rand.Reader, &leafCertTemplate, rootCA, pubKey, rootCAPrivateKey)
  if err != nil {
    return nil, nil, err
  }

  leafCertPrivateKeyDER, err = MarshalPrivateKey(privKey)

  return leafCertDER, leafCertPrivateKeyDER, err
}

// ConvertToPEM converts a DER encoded private key or certificate to PEM
// If isCert == false, then it's a key file, otherwise it's a certificate
func ConvertToPEM(derBlob []byte, isCert bool) []byte {

  pemBlock := pem.Block{}
  // If it's a certificate
  if isCert {
    pemBlock = pem.Block {
      Type: "CERTIFICATE",
      Bytes: derBlob,
    }

  } else {

    switch _, keyType, _ := ParsePrivateKey(derBlob); keyType {
    case "RSA":
      pemBlock = pem.Block {
        Type: "RSA PRIVATE KEY",
        Bytes: derBlob,
      }
    case "EC":
      pemBlock = pem.Block {
        Type: "EC PRIVATE KEY",
        Bytes: derBlob,
      }
    default:
      return nil
    }

  }

  return pem.EncodeToMemory(&pemBlock)
}

// UnMarshalPrivateKey parses a DER blob containing a private key
// Returns an object containing the parsed private key and its type
// Type is a string containing "EC" or "RSA"
// If key is malformed nil is returned with an error
func ParsePrivateKey(derBlob []byte) (parsedPrivateKey interface{}, keyType string, err error) {
  // First check if it is an RSA key
  parsedPrivateKey, err = x509.ParsePKCS1PrivateKey(derBlob)
  // If we get an error, it might be an EC key or malformed
  if err != nil {
    parsedPrivateKey, err = x509.ParseECPrivateKey(derBlob)
    if err != nil {
      return nil, "", err  // if we encounter an error then the key is malformed (or not EC/RSA)
    }
    // Because we have a return inside the if, this is essentially the else part
    // If ParseECPrivateKey was sucessfulthen it's an EC key
    keyType = "EC"
    return parsedPrivateKey, keyType, err // no naked returns
  }
  // If ParsePKCS1PrivateKey was successful then it's an RSA key
  keyType = "RSA"
  return parsedPrivateKey, keyType, err

  // I could do a bunch of if-else and do only one return in the end, but I think this is more readable
}

// MarshalPrivateKey converts a private key blob into DER format
// Input is in form of interface{} containing a *rsa.PrivateKey or *ecdsa.PrivateKey:
// Output is the private key in DER format
func MarshalPrivateKey(privateKey interface{}) (privateKeyDER []byte, err error) {

  switch tempPrivKey := privateKey.(type) {
  case *rsa.PrivateKey:
    privateKeyDER = x509.MarshalPKCS1PrivateKey(tempPrivKey) // https://golang.org/pkg/crypto/x509/#MarshalPKCS1PrivateKey - does not return error for some reason unlike the other two
  case *ecdsa.PrivateKey:
    privateKeyDER, err = x509.MarshalECPrivateKey(tempPrivKey)  // https://golang.org/pkg/crypto/x509/#MarshalECPrivateKey
    if err != nil {
      return nil, err
    }
  default:
    // This should not happen (famous last words before crashing)
    err = errors.New("Private key algorithm is neither RSA nor ECDSA")
  }

  return privateKeyDER, err

}

// GetRootCA returns the rootCA in DER format and corresponding private key
// If RootCACertFile and RootCAKeyFile exist (both in DER format) then they will be read and returned
// If these files do not exist, err will contain an error message
func ReadRootCA(RootCACertFile string, RootCAKeyFile string) (rootCA []byte, rootKey []byte, err error) {

  // Check if files exist
  rootCAExists, err := FileExists(RootCACertFile)
  if err != nil {
    return nil, nil, err
  }

  rootKeyExists, err := FileExists(RootCAKeyFile)
  if err != nil {
    return nil, nil, err
  }

  // We need both key and cert to exist
  if (rootCAExists && rootKeyExists) {

    // If files exist, read rootCA first
    rootCA, err = ioutil.ReadFile(RootCACertFile)
    if err != nil {
      return nil, nil, errors.New(fmt.Sprintf("Error reading %s file", RootCACertFile))
    }

    // Now check if rootCA is a valid DER certificate
    if _, err = x509.ParseCertificate(rootCA); err != nil {
      return nil, nil, err
    }

    // Read rootKey
    rootKey, err = ioutil.ReadFile(RootCAKeyFile)
    if err != nil {
      return nil, nil, errors.New(fmt.Sprintf("Error reading %s file", RootCAKeyFile))
    }

    // Check if rootKey is a valid key - we already have tlsdump.ParsePrivateKey that does this
    if _, _, err = ParsePrivateKey(rootKey); err != nil {
      return nil, nil, err
    }

    return rootCA, rootKey, nil

  } else {
    // Custom error text
    var customError = ""

    if !rootCAExists {
      customError += fmt.Sprintf("%s does not exist", RootCACertFile)
    }

    if !rootKeyExists {
      customError += fmt.Sprintf("\n%s does not exist", RootCAKeyFile)
    }

    return nil, nil, errors.New("customError")
  }

  // We should not get there (because both if and else have returns) but just in case
  return nil, nil, err

}

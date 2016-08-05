I decided to learn Go by creating a TLS dump proxy.

`certhelper.go` contains some of the helper methods I wrote to generate CAs and leaf certs, as well as certificate parsing.

`generateCA-test.go` is a small program that I created to test the `generateCA` function.

## Some certhelper functions
Copy pasted because I am lazy

``` go
// GenerateKeypair create a pair of public/private keys for use in a certificate.
// Valid choices for algo are "RSA" and "ECDSA" (case-insensitive).
// If ECDSA is chosen then ecCurve will contain the curve, valid values are P224, P256, P384 and P521 (case-insensitive).
// Returns an empty interface containing the keypair.
func generateKeyPair(algo string, ecCurve string) (privateKey interface{}, publicKey interface{}, err error)

// GenerateCA creates a root certificate authority using the provided information.
// Returns the a self-signed root CA, private key and error if any.
func GenerateCA(commonName string,
  serialNumber int64,
  countryCode string,
  organizationalUnit string,
  algo string,
  ecCurve string) (rootCADER []byte, rootPrivateKeyDER []byte, err error)

// GenerateAndSignLeafCert creates and signs a leaf certificate.
// Returns signed leaf cert and private key both in DER format.
func GenerateAndSignLeafCert(commonName string,
  serialNumber int64,
  countryCode string,
  organizationalUnit string,
  algo string,
  ecCurve string,
  rootCADER []byte,
  rootPrivateKeyDER []byte) (leafCertDER []byte, leafCertPrivateKeyDER []byte, err error)

// ConvertToPEM converts a DER encoded private key or certificate to PEM
// If isCert == false, then it's a key file, otherwise it's a certificate
func ConvertToPEM(derBlob []byte, isCert bool) []byte

// UnMarshalPrivateKey parses a DER blob containing a private key
// Returns an object containing the parsed private key and its type
// Type is a string containing "EC" or "RSA"
// If key is malformed nil is returned with an error
func ParsePrivateKey(derBlob []byte) (parsedPrivateKey interface{}, keyType string, err error)

// MarshalPrivateKey converts a private key blob into DER format
// Input is in form of interface{} containing a *rsa.PrivateKey or *ecdsa.PrivateKey:
// Output is the private key in DER format
func MarshalPrivateKey(privateKey interface{}) (privateKeyDER []byte, err error)

// GetRootCA returns the rootCA in DER format and corresponding private key
// If RootCACertFile and RootCAKeyFile exist (both in DER format) then they will be read and returned
// If these files do not exist, err will contain an error message
func ReadRootCA(RootCACertFile string, RootCAKeyFile string) (rootCA []byte, rootKey []byte, err error)

 
```

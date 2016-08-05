package tlsdump_test

import (
  "tlsdump"
  "fmt"
  "crypto/x509"
  "encoding/hex"
)

// Testing the tlsdump.GenerateCA function

func main() {

  // Prepare for wall of hex

  // Test RSA root CA generation
  fmt.Println("Testing root CA generation using RSA key")

  fmt.Printf("\nGenerateCA(\"*.whatever.com\", 1234, \"US\", \"Organization\", \"RSA\", \"\")")

  rootCA, privateKey, err := tlsdump.GenerateCA("*.whatever.com", 0, "US", "Organization", "RSA", "")
  if err != nil {
    fmt.Printf("\nFailed CA generation with RSA key: %v", err)
  } else {
    // Parse the cert to see if it is valid
    rsaCert, err := x509.ParseCertificate(rootCA)
    if err != nil {
      fmt.Printf("\nError during parsing the root CA with RSA key: %v", err)
    } else {
      // Print the parsed cert, this is ugly
      fmt.Printf("\nParsed Cert: %+v", rsaCert)
      fmt.Println("\n------------------------------------------------")
    }

    // Check the key pair
    // First create a valid *rsaPrivateKey from the DER encoded byte blob - https://golang.org/pkg/crypto/x509/#ParsePKCS1PrivateKey
    myRSAPrivateKey, err := x509.ParsePKCS1PrivateKey(privateKey)
    if err != nil {
      fmt.Printf("\nCould not parse the RSA DER encoded key pair: %v", err)
    } else {
        // Check if the key is valid - https://golang.org/pkg/crypto/rsa/#PrivateKey.Validate
        err := myRSAPrivateKey.Validate()
        if err != nil {
          fmt.Printf("\nError during RSA key pair validation: %v", err)
        }
    }

  fmt.Printf("\nrootCA\nType: %T\nContents:\n%s", rootCA, hex.Dump(rootCA))
  fmt.Printf("\nprivateKey\nType: %T\nContents:\n%s", privateKey, hex.Dump(privateKey))

  fmt.Println("\n------------------------------------------------")
  }

  // Test ECDSA root CA generation
  fmt.Println("Testing root CA generation using ECDSA curves")

  curves := []string{"P224", "P256", "P384", "P521"}

  for _, curve := range curves {

    fmt.Printf("\nGenerateCA(\"*.whatever.com\", 1234, \"US\", \"Organization\", \"ECDSA\", %s)", curve)

    rootCA, privateKey, err := tlsdump.GenerateCA("*.whatever.com", 0, "US", "Organization", "ECDSA", curve)
    if err != nil {
      fmt.Printf("\nFailed CA generation with ECDSA key curve %s: %v", curve, err)
    } else {
      // Parse the cert to see if it is valid
      rsaCert, err := x509.ParseCertificate(rootCA)
      if err != nil {
        fmt.Printf("\nError during parsing the root CA ECDSA key curve %s: %v", curve, err)
      } else {
        // Print the parsed cert, this is ugly
        fmt.Printf("\nParsed Cert: %+v", rsaCert)
        fmt.Println("\n------------------------------------------------")
      }

      // Check the key pair
      // First create a valid *rsaPrivateKey from the DER encoded byte blob - https://golang.org/pkg/crypto/x509/#ParseECPrivateKey
      myECDSAPrivateKey, err := x509.ParseECPrivateKey(privateKey)
      if err != nil {
        fmt.Printf("\nCould not parse the RSA DER encoded key pair: %v", err)
      } else {
          // Validate the ECDSA key pair here
          // Seems like there's not method to validate the generated ECDSA key pair - https://golang.org/pkg/crypto/ecdsa/#PrivateKey
          _ = myECDSAPrivateKey // bypass the warning
      }

      fmt.Printf("\nrootCA\nType: %T\nContents:\n%s", rootCA, hex.Dump(rootCA))
      fmt.Printf("\nprivateKey\nType: %T\nContents:\n%s", privateKey, hex.Dump(privateKey))

    fmt.Println("\n------------------------------------------------")
    }

  }

}

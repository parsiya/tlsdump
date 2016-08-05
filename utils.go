// Misc functions for tlsdump

package tlsdump

import (
  "os"
)

// fileExists returns true if a file exists
func FileExists(fileName string) (bool, error) {

  _, errFileExists := os.Stat(fileName)
  if os.IsNotExist(errFileExists) {
    return false, nil
  } else {
    return true, errFileExists
  }

}

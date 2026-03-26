//go:build !unix

package scanner

import "os"

func fileOwner(os.FileInfo) string {
	return ""
}

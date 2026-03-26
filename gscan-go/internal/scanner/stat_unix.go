//go:build unix

package scanner

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func fileOwner(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	usr, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err != nil {
		return ""
	}
	return usr.Username
}

package source

import (
	"errors"
	"os"
	"syscall"
)

func getDeviceID(fi os.FileInfo) (uint64, error) {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("error processing stat")
	}
	return stat.Dev, nil
}
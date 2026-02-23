package buffer

import (
	"io"
)

func CopyU(dst io.Writer, src io.Reader) error {
	bp := GetUDP()
	defer PutUDP(bp)

	_, err := io.CopyBuffer(dst, src, *bp)
	return err
}

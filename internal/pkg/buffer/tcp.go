package buffer

import (
	"io"
)

func CopyT(dst io.Writer, src io.Reader) error {
	bp := GetTCP()
	defer PutTCP(bp)

	_, err := io.CopyBuffer(dst, src, *bp)
	return err
}

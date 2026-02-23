package buffer

import "sync"

var (
	TPool int
	UPool int
	tPool *sync.Pool
	uPool *sync.Pool
)

func Initialize(tBuf, uBuf int) {
	TPool = tBuf
	UPool = uBuf
	tPool = &sync.Pool{New: func() any { b := make([]byte, tBuf); return &b }}
	uPool = &sync.Pool{New: func() any { b := make([]byte, uBuf); return &b }}
}

func GetTCP() *[]byte  { return tPool.Get().(*[]byte) }
func PutTCP(b *[]byte) { tPool.Put(b) }

func GetUDP() *[]byte  { return uPool.Get().(*[]byte) }
func PutUDP(b *[]byte) { uPool.Put(b) }

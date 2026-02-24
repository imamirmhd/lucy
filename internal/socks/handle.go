package socks

import (
	"context"
	"lucy/internal/tnet"
)

type Handler struct {
	provider    tnet.StreamProvider
	ctx         context.Context
	rateLimiter *rateLimiter
}

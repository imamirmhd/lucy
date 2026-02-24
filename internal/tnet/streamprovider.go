package tnet

// StreamProvider abstracts the ability to open TCP/UDP streams.
// Both client.Client and server.Client implement this interface,
// enabling socks5 and forward packages to work on either side.
type StreamProvider interface {
	TCP(addr string) (Strm, error)
	TCPBond(addr string, count int) ([]Strm, error)
	UDP(lAddr, tAddr string) (Strm, bool, uint64, error)
	CloseUDP(key uint64) error
}

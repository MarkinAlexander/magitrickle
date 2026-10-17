package dnsMITMProxy

import (
	"context"
	"errors"
	"net"
	"sync"
)

// connPool is a simple connection pool based on a channel
type connPool struct {
	network string
	addr    string
	dial    func(ctx context.Context) (net.Conn, error)
	pool    chan net.Conn
	maxIdle uint
	mu      sync.Mutex
	closed  bool
}

func newConnPool(network, addr string, maxIdle uint) *connPool {
	return newConnPoolDial(network, addr, maxIdle, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})
}

// newConnPoolDial - пул с кастомным диалом (DoT: TCP + TLS-хендшейк).
func newConnPoolDial(network, addr string, maxIdle uint, dial func(ctx context.Context) (net.Conn, error)) *connPool {
	return &connPool{
		network: network,
		addr:    addr,
		dial:    dial,
		pool:    make(chan net.Conn, maxIdle),
		maxIdle: maxIdle,
	}
}

func (p *connPool) Get(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("pool is closed")
	}
	p.mu.Unlock()

	// Check context before trying to get/create connection
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	select {
	case conn := <-p.pool:
		return conn, nil
	default:
		return p.dial(ctx)
	}
}

func (p *connPool) Put(conn net.Conn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return
	}
	p.mu.Unlock()

	select {
	case p.pool <- conn:
	default:
		_ = conn.Close()
	}
}

func (p *connPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()

	close(p.pool)
	for conn := range p.pool {
		_ = conn.Close()
	}
}

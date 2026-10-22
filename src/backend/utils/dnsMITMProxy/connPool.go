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
	return p.get(ctx, true)
}

func (p *connPool) get(ctx context.Context, reuse bool) (net.Conn, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("pool is closed")
	}
	// Check context before trying to get/create connection
	if ctx.Err() != nil {
		p.mu.Unlock()
		return nil, ctx.Err()
	}

	if reuse {
		select {
		case conn := <-p.pool:
			p.mu.Unlock()
			return conn, nil
		default:
		}
	}
	p.mu.Unlock()
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		_ = conn.Close()
		return nil, errors.New("pool is closed")
	}
	return conn, nil
}

func (p *connPool) Put(conn net.Conn) {
	p.mu.Lock()
	if !p.closed {
		select {
		case p.pool <- conn:
			p.mu.Unlock()
			return
		default:
		}
	}
	p.mu.Unlock()
	_ = conn.Close()
}

func (p *connPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.pool)
	p.mu.Unlock()

	for conn := range p.pool {
		_ = conn.Close()
	}
}

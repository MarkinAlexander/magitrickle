package dnsMITMProxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Виды апстримов каскада dns-proxy: plain host:port (как было), DoT
// tls://host[:853] (RFC 7858: TCP + TLS) и DoH https://host[:443]/path
// (RFC 8484, POST application/dns-message, путь по умолчанию /dns-query).
type upKind int

const (
	upPlain upKind = iota
	upDoT
	upDoH
)

func (k upKind) String() string {
	switch k {
	case upDoT:
		return "dot"
	case upDoH:
		return "doh"
	}
	return "plain"
}

// parsedUpstream - разобранный адрес апстрима. addr - каноническое
// представление (оно же идентификатор в снимке состояния и конфиге),
// dialAddr - host:port для plain/DoT, dohURL - конечная точка DoH.
type parsedUpstream struct {
	kind       upKind
	addr       string
	dialAddr   string
	dohURL     *url.URL
	serverName string // TLS SNI: имя хоста или сам IP (сертификаты с IP-SAN)
	port       uint16
}

// parseUpstreamAddr разбирает адрес апстрима. plain-адреса приходят сюда
// уже каноническими host:port (их собирает dnsUpstreamAddrs), для схем
// достраиваются умолчания портов и пути DoH.
// ParseUpstreamAddr - экспорт для валидации на слое приложения (dnsupstreams).
func ParseUpstreamAddr(raw string) (parsedUpstream, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "tls://"):
		rest := strings.TrimPrefix(raw, "tls://")
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			return parsedUpstream{}, fmt.Errorf("путь не имеет смысла для DoT: %q", raw)
		}
		host, portStr := splitHostPortDefault(rest, "853")
		if host == "" {
			return parsedUpstream{}, fmt.Errorf("нет хоста в %q", raw)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return parsedUpstream{}, fmt.Errorf("порт в %q", raw)
		}
		dial := net.JoinHostPort(host, portStr)
		return parsedUpstream{kind: upDoT, addr: "tls://" + dial, dialAddr: dial, serverName: host, port: uint16(port)}, nil
	case strings.HasPrefix(raw, "https://"):
		u, err := url.Parse(raw)
		if err != nil {
			return parsedUpstream{}, fmt.Errorf("%q: %v", raw, err)
		}
		host := u.Hostname()
		if host == "" {
			return parsedUpstream{}, fmt.Errorf("нет хоста в %q", raw)
		}
		portStr := u.Port()
		if portStr == "" {
			portStr = "443"
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return parsedUpstream{}, fmt.Errorf("порт в %q", raw)
		}
		path := u.EscapedPath()
		if path == "" || path == "/" {
			path = "/dns-query"
		}
		u2 := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, portStr), Path: path}
		return parsedUpstream{kind: upDoH, addr: u2.String(), dohURL: u2, serverName: host, port: uint16(port)}, nil
	case strings.Contains(raw, "://"):
		return parsedUpstream{}, fmt.Errorf("неизвестная схема в %q (поддержаны tls:// и https://)", raw)
	}
	// plain: host:port без схемы - как было до DoT/DoH
	return parsedUpstream{kind: upPlain, addr: raw, dialAddr: raw, port: 53}, nil
}

func splitHostPortDefault(hostport, defPort string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return strings.Trim(hostport, "[]"), defPort
}

func tlsConfigFor(p parsedUpstream, override *tls.Config) *tls.Config {
	if override != nil {
		return override
	}
	// ServerName допускает IP-литерал: go сверяет его с IP-SAN
	// (сертификаты 1.1.1.1/8.8.8.8 их содержат)
	return &tls.Config{ServerName: p.serverName, MinVersion: tls.VersionTLS12}
}

// dohExchange - один DoH-обмен (RFC 8484): POST application/dns-message.
// Используется и клиентским путём, и зондом-канарейкой; http-клиент
// держит keep-alive, таймаут - через контекст запроса.
func dohExchange(ctx context.Context, u *upstream, req []byte, timeout time.Duration) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rq, err := http.NewRequestWithContext(cctx, http.MethodPost, u.dohURL.String(), bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Content-Type", "application/dns-message")
	rq.Header.Set("Accept", "application/dns-message")
	resp, err := u.doh.Do(rq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("doh: статус %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
}

func dotExchangeOnce(ctx context.Context, u *upstream, req []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var q dns.Msg
	if err := q.Unpack(req); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		conn, getErr := u.dot.get(ctx, attempt == 0)
		if getErr != nil {
			return nil, getErr
		}
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
		var resp []byte
		resp, err = dnsFramedExchange(conn, req)
		if err != nil {
			_ = conn.Close()
			var netErr net.Error
			if !errors.As(err, &netErr) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, err
			}
			continue
		}
		var msg dns.Msg
		if err := msg.Unpack(resp); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if msg.Id != q.Id {
			_ = conn.Close()
			return nil, errAnswerMismatch
		}
		u.dot.Put(conn)
		return resp, nil
	}
	return nil, err
}

// dnsFramedExchange - DNS-over-TCP фрейминг (2-байтовый префикс длины).
func dnsFramedExchange(conn net.Conn, req []byte) ([]byte, error) {
	if _, err := conn.Write([]byte{byte(len(req) >> 8), byte(len(req))}); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen == 0 || respLen > maxTCPMsgSize {
		return nil, fmt.Errorf("некорректная длина ответа: %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Addr - каноническое представление апстрима (идентификатор конфига).
func (p parsedUpstream) Addr() string { return p.addr }

// Port - порт апстрима (853/443/53 в зависимости от вида).
func (p parsedUpstream) Port() uint16 { return p.port }

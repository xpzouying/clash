package http

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"time"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/log"
	authStore "github.com/Dreamacro/clash/proxy/auth"
	"github.com/Dreamacro/clash/tunnel"
)

type HttpListener struct {
	net.Listener
	// 只是为了返回监听的具体地址
	address string
	closed  bool
	cache   *cache.Cache
}

// NewHttpProxy 建立http代理监听
func NewHttpProxy(addr string) (*HttpListener, error) {
	// 这里使用了自己建立tcp连接，进行监听到处理连接
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	hl := &HttpListener{l, addr, false, cache.New(30 * time.Second)}

	go func() {
		log.Infoln("HTTP proxy listening at: %s", addr)

		for {
			c, err := hl.Accept()
			if err != nil {
				if hl.closed {
					break
				}
				continue
			}
			go HandleConn(c, hl.cache)
		}
	}()

	return hl, nil
}

func (l *HttpListener) Close() {
	l.closed = true
	l.Listener.Close()
}

func (l *HttpListener) Address() string {
	return l.address
}

func canActivate(loginStr string, authenticator auth.Authenticator, cache *cache.Cache) (ret bool) {
	if result := cache.Get(loginStr); result != nil {
		ret = result.(bool)
		return
	}
	loginData, err := base64.StdEncoding.DecodeString(loginStr)
	login := strings.Split(string(loginData), ":")
	ret = err == nil && len(login) == 2 && authenticator.Verify(login[0], login[1])

	cache.Put(loginStr, ret, time.Minute)
	return
}

// HandleConn 处理请求的连接。发起一次连接的时候，就会进入到这个函数进行处理。
func HandleConn(conn net.Conn, cache *cache.Cache) {
	log.Debugln("[zy-debug] HandleConn: handle a new connection: %+v", conn)
	defer func() {
		log.Debugln("[zy-debug Handle Conn: call defer, function finish")
	}()

	br := bufio.NewReader(conn)

keepAlive:

	// 通过 http.ReadRequest 读出来 http 的信息
	request, err := http.ReadRequest(br)
	if err != nil || request.URL.Host == "" {
		conn.Close()
		return
	}

	log.Debugln("[zy-debug] HandleConn: http request: %+v", request)

	// 如果是 keepalive，则一直拿着这个连接。相当于这个协程一直在后台工作，为这个连接服务，不退出。
	// HTTP keepAlive的介绍：https://zh.wikipedia.org/wiki/HTTP%E6%8C%81%E4%B9%85%E8%BF%9E%E6%8E%A5
	keepAlive := strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"
	authenticator := authStore.Authenticator()
	if authenticator != nil {
		if authStrings := strings.Split(request.Header.Get("Proxy-Authorization"), " "); len(authStrings) != 2 {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			if keepAlive {
				goto keepAlive
			}
			return
		} else if !canActivate(authStrings[1], authenticator, cache) {
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			log.Infoln("Auth failed from %s", conn.RemoteAddr().String())
			if keepAlive {
				goto keepAlive
			}
			conn.Close()
			return
		}
	}

	// 创建连接时，会接收到2种情况的请求：一种是CONNECT命令；另外就是其他。
	// 接收到请求后需要将连接加入到tunnel的连接池里面。（其中使用channel实现）
	// 如果是 CONNECT 指令，那么需要回复请求端连接已经建立。
	if request.Method == http.MethodConnect {
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			conn.Close()
			return
		}

		// 加入连接队列中
		tunnel.Add(adapters.NewHTTPS(request, conn))
		return
	}

	// 加入连接队列中
	tunnel.Add(adapters.NewHTTP(request, conn))
}

package vtunnel

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"
)

func (s *Server) SetDomainMapping(domain, target string) {
	s.domainMu.Lock()
	s.domainMap[domain] = target
	s.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping added: %s -> %s", domain, target)
}

func (s *Server) RemoveDomainMapping(domain string) {
	s.domainMu.Lock()
	delete(s.domainMap, domain)
	s.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping removed: %s", domain)
}

func (s *Server) resolveDomain(host string) (string, bool) {
	s.domainMu.RLock()
	target, ok := s.domainMap[host]
	s.domainMu.RUnlock()
	return target, ok
}

func (s *Server) StartProxy(addr string) error {
	proxy := goproxy.NewProxyHttpServer()

	if s.mitmCA != nil {
		goproxy.GoproxyCa = *s.mitmCA
		mitmConnect := &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: goproxy.TLSConfigFromCA(&goproxy.GoproxyCa),
		}

		proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				if _, ok := s.resolveDomain(host); ok {
					log.Printf("[vtunnel-proxy] CONNECT MITM %s", host)
					return mitmConnect, host
				}
				log.Printf("[vtunnel-proxy] CONNECT %s -> direct", host)
				return goproxy.OkConnect, host
			}))
	} else {
		proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				if mapped, ok := s.resolveDomain(host); ok {
					log.Printf("[vtunnel-proxy] CONNECT %s -> %s", host, mapped)
					return goproxy.OkConnect, mapped
				}
				log.Printf("[vtunnel-proxy] CONNECT %s -> direct", host)
				return goproxy.OkConnect, host
			}))
	}

	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			hostPort := req.Host
			if _, _, err := net.SplitHostPort(hostPort); err != nil {
				port := "80"
				if req.URL.Scheme == "https" {
					port = "443"
				}
				hostPort = net.JoinHostPort(hostPort, port)
			}
			if mapped, ok := s.resolveDomain(hostPort); ok {
				log.Printf("[vtunnel-proxy] %s %s %s -> %s", req.URL.Scheme, req.Method, hostPort, mapped)
				req.URL.Host = mapped
				req.URL.Scheme = "http"
			}
			return req, nil
		})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen on %s: %w", addr, err)
	}

	s.proxyListener = ln
	s.proxyDone = make(chan struct{})
	s.proxyOnce = sync.Once{}

	log.Printf("[vtunnel-proxy] Listening on %s", addr)

	go http.Serve(ln, proxy)

	return nil
}

func (s *Server) CloseProxy() {
	s.proxyOnce.Do(func() {
		if s.proxyDone != nil {
			close(s.proxyDone)
		}
		if s.proxyListener != nil {
			s.proxyListener.Close()
		}
	})
}

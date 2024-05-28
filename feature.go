package main

import (
	// comment out the services you don't need to make the compiled binary smaller.
	// _ "github.com/meoww-bot/glider/service/xxx"

	// comment out the protocols you don't need to make the compiled binary smaller.
	_ "github.com/meoww-bot/glider/proxy/http"
	_ "github.com/meoww-bot/glider/proxy/kcp"
	_ "github.com/meoww-bot/glider/proxy/mixed"
	_ "github.com/meoww-bot/glider/proxy/obfs"
	_ "github.com/meoww-bot/glider/proxy/pxyproto"
	_ "github.com/meoww-bot/glider/proxy/reject"
	_ "github.com/meoww-bot/glider/proxy/smux"
	_ "github.com/meoww-bot/glider/proxy/socks4"
	_ "github.com/meoww-bot/glider/proxy/socks5"
	_ "github.com/meoww-bot/glider/proxy/ss"
	_ "github.com/meoww-bot/glider/proxy/ssh"
	_ "github.com/meoww-bot/glider/proxy/ssr"
	_ "github.com/meoww-bot/glider/proxy/tcp"
	_ "github.com/meoww-bot/glider/proxy/tls"
	_ "github.com/meoww-bot/glider/proxy/trojan"
	_ "github.com/meoww-bot/glider/proxy/udp"
	_ "github.com/meoww-bot/glider/proxy/vless"
	_ "github.com/meoww-bot/glider/proxy/vmess"
	_ "github.com/meoww-bot/glider/proxy/ws"
)

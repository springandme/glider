package smux

import "github.com/meoww-bot/glider/proxy"

func init() {
	proxy.AddUsage("smux", `
Smux scheme:
  smux://host:port
`)
}

// Command kandev-provider-hostd is the Kandev plugin binary (runtime.type:
// binary). Kandev spawns it and talks gRPC via hashicorp/go-plugin.
package main

import (
	"github.com/gyhu-labs/kandev-provider-hostd/internal/provider"
	"github.com/kdlbs/kandev/pluginsdk"
)

func main() {
	pluginsdk.Serve(provider.New())
}

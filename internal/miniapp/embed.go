// Package miniapp serves the static Telegram Mini App used by the
// remofy-bot project to enrol and unlock MFA. Files live under static/
// and are baked into the binary via //go:embed.
package miniapp

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var assetsFS embed.FS

// Handler returns an http.Handler that serves the Mini App under /mfa/bot/.
// Bare path resolves to index.html.
func Handler() http.Handler {
	sub, err := fs.Sub(assetsFS, "static")
	if err != nil {
		panic(err) // baked at build time, can't fail
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.StripPrefix("/mfa/bot", fileServer)
}

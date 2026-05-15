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
//
// Telegram mobile WebViews cache Mini App assets aggressively — without
// Cache-Control headers users keep loading an old app.js after a deploy.
// We disable caching outright; the payload is tiny and ships once per
// unlock ceremony.
func Handler() http.Handler {
	sub, err := fs.Sub(assetsFS, "static")
	if err != nil {
		panic(err) // baked at build time, can't fail
	}
	fileServer := http.FileServer(http.FS(sub))
	stripped := http.StripPrefix("/mfa/bot", fileServer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		stripped.ServeHTTP(w, r)
	})
}

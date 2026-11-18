//go:build tools

// Package gomobiletools pins golang.org/x/mobile as a direct dependency so
// `gomobile bind` can find the binding runtime for this module.
package gomobiletools

import (
	_ "golang.org/x/mobile/bind"
)

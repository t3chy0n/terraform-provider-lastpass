package client

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"last-pass/client/client_errors"
	_ "last-pass/client/client_errors"
	"last-pass/client/dto"
	"last-pass/client/kdf"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// MaxLoginRetries determines the maximum number of login retries
// if the login fails with cause "outofbandrequired".
// This increases the user's time to approve the out-of-band (2nd) factor
// (e.g. approving a push notification sent to their mobile phone).
const (
	MaxLoginRetries = 7
)
const LAST_PASS_SERVER = "https://lastpass.com"
const (
	EndpointLogin             = "/login.php"
	EndpointTrust             = "/trust.php"
	EndpointIterations        = "/iterations.php"
	EndpointLoginCheck        = "/login_check.php"
	EndpointAttachment        = "/getattach.php"
	EndpointGetAccts          = "/getaccts.php"
	EndpointShowWebsite       = "/show_website.php"
	EndpointAddApplication    = "/addapp.php"
	EndpointFieldsIncremental = "/fields.php"
	EndpointFields            = "/gm_deliver.php"
	//EndpointShow            = "/show.php"
	EndpointCustomTemplates = "/lmiapi/note-templates"
	EndpointCSRF            = "/getCSRFToken.php"
	EndpointLogout          = "/logout.php"
)

const (
	fileTrustID           = "trusted_id"
	allowedCharsInTrustID = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$"
	trustLabelApp         = "ExternalSecretsController"
)

type LastPassClient struct {
	httpClient *http.Client
	Session    *dto.Session
	logger     *Logger

	ctx        *context.Context
	iterations int
	otp        string
	trustId    string
	trustLabel string
	BaseUrl    string

	KDFLoginKey      []byte
	KDFDecryptionKey []byte

	trust bool
}
type ClientOption func(c *LastPassClient)
type RequestOption func(c *http.Request)

func NewClient(username string, masterPassword string, opts ...ClientOption) (*LastPassClient, error) {
	var err error
	if username == "" {
		return nil, &client_errors.Authentication{"username must not be empty"}
	}
	if masterPassword == "" {
		return nil, &client_errors.Authentication{"masterPassword must not be empty"}
	}
	client, err := setupClient(opts...)
	if err != nil {
		return nil, err
	}
	client.iterations, err = client.getHashingIterations(username)
	if err != nil {
		fmt.Println("Problem with fetching iterations count:", err)
		return nil, err
	}

	client.KDFLoginKey = kdf.LoginKey(username, masterPassword, client.iterations)
	client.KDFDecryptionKey = kdf.DecryptionKey(username, masterPassword, client.iterations)

	if err != nil {
		fmt.Println("Problem with calculating trust id:", err)
	}
	currentSession, err := client.login(username)
	if err != nil {
		return nil, err
	}

	client.Session = currentSession

	client.Session.CSRFToken, err = client.getCSRFToken()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func setupClient(opts ...ClientOption) (*LastPassClient, error) {
	c := &LastPassClient{
		BaseUrl: LAST_PASS_SERVER,
	}

	for _, opt := range opts {
		opt(c)
	}
	if c.httpClient == nil {
		cookieJar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		c.httpClient = &http.Client{
			Jar: cookieJar,
		}
	}

	return c, nil
}

func WithTrust() ClientOption {
	return func(c *LastPassClient) {
		c.trust = true
	}
}
func WithTrustId(id string) ClientOption {
	return func(c *LastPassClient) {
		c.trustId = id
	}
}
func WithTrustLabel(label string) ClientOption {
	return func(c *LastPassClient) {
		c.trustLabel = label
	}
}
func WithContext(ctx *context.Context) ClientOption {
	return func(c *LastPassClient) {
		c.ctx = ctx
	}
}

func WithLogger(logger Logger) ClientOption {
	return func(c *LastPassClient) {
		c.logger = &logger
	}
}

func (c *LastPassClient) calculateTrustLabel() error {
	if c.trust {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		c.trustLabel = fmt.Sprintf("%s %s %s", hostname, runtime.GOOS, trustLabelApp)
	}
	return nil
}

func WithUrlParams(params url.Values) RequestOption {
	return func(req *http.Request) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = io.NopCloser(strings.NewReader(params.Encode()))
	}
}

func WithJsonBody[T any](data T) RequestOption {
	return func(req *http.Request) {
		req.Header.Set("Content-Type", "application/json")
		jsonData, _ := json.Marshal(data)

		req.Body = io.NopCloser(strings.NewReader(string(jsonData)))
	}
}
func WithMethod(method string) RequestOption {
	return func(req *http.Request) {
		req.Method = method
	}
}

func WithCookies(cookies map[string]string) RequestOption {
	return func(req *http.Request) {
		for key, value := range cookies {
			cookie := &http.Cookie{
				Name:  key,
				Value: value,
				// other cookie fields if needed
			}
			req.AddCookie(cookie)
		}
	}
}

func WithHeaders(headers http.Header) RequestOption {
	return func(req *http.Request) {
		req.Header = headers
	}
}

func (lpassClient *LastPassClient) makeRequest(ctx context.Context, path string, opts ...RequestOption) ([]byte, error) {

	if lpassClient.ctx != nil {
		ctx = *lpassClient.ctx
	}

	// Send the request

	maxRetries := 8
	retryDelay := 3 * time.Second // Start with a 1-second delay
	maxDelay := time.Minute       // Maximum delay between retries

	for attempt := 0; attempt < maxRetries; attempt++ {
		client := &http.Client{}

		// Create a new request
		req, err := http.NewRequestWithContext(ctx, "POST", lpassClient.BaseUrl+path, strings.NewReader(""))
		if lpassClient.ctx != nil {
			req.WithContext(context.Background())
		}
		lpassClient.log("%s %s\n", req.Method, req.URL)
		if err != nil {
			return nil, err
		}

		for _, opt := range opts {
			opt(req)
		}

		// Set the User-Agent header
		req.Header.Set("User-Agent", "LastPass-CLI/")

		resp, err := client.Do(req)
		if err != nil {
			lpassClient.log("HTTP request failed: %v", err)
			return nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			lpassClient.log(fmt.Sprintf("Response code: %s", resp.Status))
			if err != nil {
				return nil, err
			}

			// Read the response body
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			return body, nil
		}

		// If we received a 429, wait and retry
		lpassClient.log("Received 429, retrying after %v", retryDelay)
		time.Sleep(retryDelay)

		// Exponential backoff with a max delay limit
		retryDelay *= 2
		if retryDelay > maxDelay {
			retryDelay = maxDelay
		}

		// Important: Close the previous response's body to avoid leaking resources
		resp.Body.Close()
	}

	return nil, errors.New("Request failed too many times.")

}

func xmlParse[TRes any](rawResponse []byte) (*TRes, error) {

	var response TRes
	if err := xml.Unmarshal(rawResponse, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &response, nil
}

func (lpassClient *LastPassClient) getSessionCookies() map[string]string {
	if lpassClient.Session == nil {
		return map[string]string{}
	}
	return map[string]string{
		"PHPSESSID": lpassClient.Session.SessionID,
	}
}

func (lpassClient *LastPassClient) IsAuthenticated() bool {
	return lpassClient.Session != nil
}

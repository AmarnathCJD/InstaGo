package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type Authenticator struct {
	*http.Client
	cookies       []*http.Cookie
	enableCache   bool
	authenticated bool
	currentCsrf   string
	loginNonce    string
}

func NewAuthenticator(enableCache ...bool) *Authenticator {
	authy := &Authenticator{
		Client: &http.Client{},
	}

	if len(enableCache) > 0 && enableCache[0] {
		authy.enableCache = true
		if err := authy.LoadSession(); err == nil {
			authy.authenticated = true
		}
	}

	return authy
}

func (a *Authenticator) Do(req *http.Request) (*http.Response, error) {
	for _, cookie := range a.cookies {
		req.AddCookie(cookie)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36")
	req.Header.Set("Accept", "*/*")

	return a.Client.Do(req)
}

type InstaUserMin struct {
	UserID          string `json:"userId"`
	AuthenticatedAt int64  `json:"authenticatedAt"`
	Authenticated   bool   `json:"authenticated"`
}

func (a *Authenticator) Login(username, password string) (*InstaUserMin, error) {
	_csrf, err := a.getCsrfToken()
	if err != nil {
		return nil, err
	}

	a.currentCsrf = _csrf

	req, _ := http.NewRequest("POST", "https://www.instagram.com/api/v1/web/accounts/login/ajax/", strings.NewReader(fmt.Sprintf("username=%s&enc_password=%s&queryParams={}&optIntoOneTap=true", username, a.genEncPassword(password))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-csrftoken", _csrf)

	resp, err := a.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var result struct {
			Message       string `json:"message"`
			Status        string `json:"status"`
			Authenticated bool   `json:"authenticated"`
			User          bool   `json:"user"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}

		if result.Message != "" {
			return nil, fmt.Errorf("login failed: %s", result.Message)
		}

		if result.User && !result.Authenticated {
			return nil, fmt.Errorf("login failed: possibly wrong password")
		}

		return nil, fmt.Errorf("login failed: %s", resp.Status)
	}

	var LoggedUser *InstaUserMin
	if err := json.NewDecoder(resp.Body).Decode(&LoggedUser); err != nil {
		return nil, err
	}

	if !LoggedUser.Authenticated {
		return nil, fmt.Errorf("login failed: possibly wrong password")
	}

	a.cookies = resp.Cookies()
	LoggedUser.AuthenticatedAt = time.Now().Unix()
	if a.enableCache {
		if err := a.SaveSession(); err != nil {
			return nil, err
		}
	}
	a.authenticated = true

	return LoggedUser, nil
}

func (a *Authenticator) ReqLoginNonce() (string, error) {
	req, _ := http.NewRequest("POST", "https://www.instagram.com/api/v1/web/accounts/request_one_tap_login_nonce/", nil)
	resp, err := a.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request login nonce failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`(?m)window._sharedData = (.*);</script>`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return "", fmt.Errorf("request login nonce failed: nonce not found")
	}

	var sharedData struct {
		Config struct {
			CsrfToken string `json:"csrf_token"`
		} `json:"config"`
	}

	if err := json.Unmarshal([]byte(matches[1]), &sharedData); err != nil {
		return "", err
	}

	a.loginNonce = sharedData.Config.CsrfToken

	return a.loginNonce, nil // TBA
}

func (a *Authenticator) Logout() error {
	req, _ := http.NewRequest("GET", "https://www.instagram.com/accounts/logout/", nil)
	resp, err := a.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("logout failed: %s", resp.Status)
	}

	a.cookies = nil

	return nil
}

func (a *Authenticator) GetCookies() []*http.Cookie {
	return a.cookies
}

func (a *Authenticator) SetCookies(cookies []*http.Cookie) {
	a.cookies = cookies
}

func (a *Authenticator) SaveSession() error {
	if !a.enableCache {
		return fmt.Errorf("cache is disabled")
	}

	if len(a.cookies) == 0 {
		return fmt.Errorf("no cookies to save")
	}

	cookies, err := json.Marshal(a.cookies)
	if err != nil {
		return err
	}

	file, err := os.Create("session.session")
	if err != nil {
		return err
	}

	defer file.Close()

	if _, err := file.WriteString(encodeToBase64(string(cookies))); err != nil {
		return err
	}

	return nil
}

func (a *Authenticator) LoadSession() error {
	if !a.enableCache {
		return fmt.Errorf("cache is disabled")
	}

	file, err := os.Open("session.session")
	if err != nil && !os.IsNotExist(err) {
		return err
	} else if os.IsNotExist(err) {
		return nil
	}

	defer file.Close()

	var cookies []*http.Cookie

	undecoded, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(decodeFromBase64(string(undecoded))), &cookies); err != nil {
		return err
	}

	a.cookies = cookies
	return nil
}

func (a *Authenticator) DeleteSession() error {
	if !a.enableCache {
		return fmt.Errorf("cache is disabled")
	}

	if err := os.Remove("session.json"); err != nil {
		return err
	}

	return nil
}

func (a *Authenticator) IsSessionExists() bool {
	if !a.enableCache {
		return false
	}

	if _, err := os.Stat("session.json"); os.IsNotExist(err) {
		return false
	}

	return true
}

func (a *Authenticator) ExportSession() (string, error) {
	if !a.enableCache {
		return "", fmt.Errorf("cache is disabled")
	}

	if len(a.cookies) == 0 {
		return "", fmt.Errorf("no cookies to export")
	}

	cookies, err := json.Marshal(a.cookies)
	if err != nil {
		return "", err
	}

	return encodeToBase64(string(cookies)), nil
}

func (a *Authenticator) ImportSession(session string) error {
	if !a.enableCache {
		return fmt.Errorf("cache is disabled")
	}

	var cookies []*http.Cookie

	if err := json.Unmarshal([]byte(decodeFromBase64(session)), &cookies); err != nil {
		return err
	}

	a.cookies = cookies
	return nil
}

func (a *Authenticator) ExportSessionID() (string, error) {
	for _, cookie := range a.cookies {
		if cookie.Name == "sessionid" {
			return cookie.Value, nil
		}
	}

	return "", fmt.Errorf("sessionid not found")
}

func (a *Authenticator) ImportSessionID(sessionID string) error {
	for _, cookie := range a.cookies {
		if cookie.Name == "sessionid" {
			cookie.Value = sessionID
			return nil
		}
	}

	return fmt.Errorf("sessionid not found")
}

func (a *Authenticator) SetProxy(proxy string) error {
	if proxy == "" {
		return fmt.Errorf("proxy is empty")
	}

	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return err
	}

	a.Client.Transport = &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	return nil
}

func encodeToBase64(str string) string {
	return base64.URLEncoding.Strict().EncodeToString([]byte(str))
}

func decodeFromBase64(str string) string {
	decoded, _ := base64.URLEncoding.Strict().DecodeString(str)
	return string(decoded)
}

func (a *Authenticator) genEncPassword(password string) string {
	return "#PWD_INSTAGRAM_BROWSER:0:0:" + password // workaround hehe :v
}

func (a *Authenticator) getCsrfToken() (string, error) {
	req, _ := http.NewRequest("GET", "https://www.instagram.com/accounts/login/", nil)
	resp, err := a.Do(req)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching csrf token: %s", resp.Status)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	csrf_token_raw_ := strings.Replace(string(body), "\\", "", -1)
	if matches := regexp.MustCompile(`"csrf_token":"(.*?)"`).FindStringSubmatch(csrf_token_raw_); len(matches) > 0 {
		return matches[1], nil
	}

	return "", fmt.Errorf("fetching csrf token: csrf token not found")
}

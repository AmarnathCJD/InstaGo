package main

import (
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
	tokCsrf       string
	appId         string
	loginNonce    string
	loggedUser    *InstaUserMin
}

func NewAuthenticator(enableCache ...bool) *Authenticator {
	authy := &Authenticator{
		Client: &http.Client{},
	}

	if len(enableCache) > 0 && enableCache[0] {
		authy.enableCache = true
		if authy.IsSessionExists() {
			if err := authy.loadSession(); err != nil {
				panic(err)
			}
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

	if a.tokCsrf == "" {
		a.tokCsrf = getCookie(a.cookies, "csrftoken")
	}

	req.Header.Set("X-Csrftoken", a.tokCsrf)
	req.Header.Set("X-Ig-App-Id", a.appId)

	return a.Client.Do(req)
}

type InstaUserMin struct {
	UserID          string `json:"userId"`
	AuthenticatedAt int64  `json:"authenticatedAt"`
	Authenticated   bool   `json:"authenticated"`
}

func (a *Authenticator) Login(username, password string) (*InstaUserMin, error) {
	if a.authenticated {
		fmt.Println("Already authenticated")
		return a.loggedUser, nil
	}
	_csrf, err := a.getCsrfToken()
	if err != nil {
		return nil, err
	}

	a.tokCsrf = _csrf

	req, _ := http.NewRequest("POST", "https://www.instagram.com/api/v1/web/accounts/login/ajax/", strings.NewReader(fmt.Sprintf("username=%s&enc_password=%s&queryParams={}&optIntoOneTap=true", username, a.genEncPassword(password))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
		return nil, fmt.Errorf("login failed: possibly wrong password/username")
	}

	a.cookies = resp.Cookies()
	LoggedUser.AuthenticatedAt = time.Now().Unix()
	if a.enableCache {
		if err := a.saveSession(); err != nil {
			return nil, err
		}
	}
	a.authenticated = true
	a.loggedUser = LoggedUser

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
	a.authenticated = false
	a.loggedUser = nil
	a.deleteSession()

	return nil
}

func (a *Authenticator) GetCookies() []*http.Cookie {
	return a.cookies
}

func (a *Authenticator) SetCookies(cookies []*http.Cookie) {
	a.cookies = cookies
}

func (a *Authenticator) saveSession() error {
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

	encodedAuth := encodeToBase64(string(cookies))
	var towrite struct {
		Auth  string `json:"auth,omitempty"`
		AppId string `json:"app_id,omitempty"`
	}

	towrite.Auth = encodedAuth
	towrite.AppId = a.appId

	if err := json.NewEncoder(file).Encode(towrite); err != nil {
		return err
	}

	return nil
}

func (a *Authenticator) loadSession() error {
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

	var decoded struct {
		Auth  string `json:"auth,omitempty"`
		AppId string `json:"app_id,omitempty"`
	}

	if err := json.Unmarshal(undecoded, &decoded); err != nil {
		return err
	}

	decodedAuth := decodeFromBase64(decoded.Auth)

	if err := json.Unmarshal([]byte(decodedAuth), &cookies); err != nil {
		return err
	}

	if decoded.AppId != a.appId && a.appId != "" && decoded.AppId != "" {
		return fmt.Errorf("app id mismatch")
	}

	a.appId = decoded.AppId

	a.cookies = cookies
	return nil
}

func (a *Authenticator) deleteSession() error {
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

	if _, err := os.Stat("session.session"); os.IsNotExist(err) {
		return false
	}

	return true
}

func (a *Authenticator) exportSession() (string, error) {
	var exportSess struct {
		Auth  string `json:"auth,omitempty"`
		AppId string `json:"app_id,omitempty"`
	}

	if cook := getCookie(a.cookies, "sessionid"); cook != "" {
		exportSess.Auth = encodeToBase64(cook)
	}

	exportSess.AppId = a.appId

	exported, err := json.Marshal(exportSess)
	if err != nil {
		return "", err
	}

	return encodeToBase64(string(exported)), nil
}

func (a *Authenticator) importSession(session string) error {
	var imported struct {
		Auth  string `json:"auth,omitempty"`
		AppId string `json:"app_id,omitempty"`
	}

	decoded := decodeFromBase64(session)

	if err := json.Unmarshal([]byte(decoded), &imported); err != nil {
		return err
	}

	if imported.AppId != a.appId && a.appId != "" && imported.AppId != "" {
		return fmt.Errorf("app id mismatch")
	}

	a.cookies = append(a.cookies, &http.Cookie{
		Name:  "sessionid",
		Value: decodeFromBase64(imported.Auth),
	})

	a.appId = imported.AppId
	return nil
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
		if matches_ := regexp.MustCompile(`"X-IG-App-ID":"(.*?)"`).FindStringSubmatch(csrf_token_raw_); len(matches_) > 0 {
			a.appId = matches_[1]
		}
		return matches[1], nil
	}

	return "", fmt.Errorf("fetching csrf token: csrf token not found")
}

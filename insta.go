// scarpe instagram.com to get getMe
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type Instagram struct {
	Authenticator *Authenticator
}

type Opts struct {
	AccessToken string // generated using .GenerateAccessToken()
	SessionID   string
	Username    string
	Password    string
	Cookies     []*http.Cookie
	EnableCache bool
}

func NewInsta(opts *Opts) (*Instagram, error) {
	auth := NewAuthenticator(opts.EnableCache)
	if opts.SessionID != "" || (opts.Username != "" && opts.Password != "") {
		if opts.SessionID != "" {
			auth.cookies = append(auth.cookies, &http.Cookie{
				Name:  "sessionid",
				Value: opts.SessionID,
			})
			auth.authenticated = true
		} else {
			if _, err := auth.Login(opts.Username, opts.Password); err != nil {
				return nil, err
			}
		}
	} else if opts.Cookies != nil {
		auth.cookies = opts.Cookies
		auth.authenticated = true
	} else if opts.AccessToken != "" {
		if err := auth.importSession(opts.AccessToken); err != nil {
			return nil, err
		}
		auth.authenticated = true
	} else {
		return nil, fmt.Errorf("either sessionId or username and password or cookies must be provided")
	}

	return &Instagram{
		Authenticator: auth,
	}, nil
}

// GenerateAccessToken generates an access token from the current session for later use.
func (i *Instagram) GenerateAccessToken() (string, error) {
	if !i.Authenticator.authenticated {
		return "", fmt.Errorf("not authenticated, please login first")
	}

	return i.Authenticator.exportSession()
}

// IsAuthenticated returns true if the current session is authenticated.
func (i *Instagram) IsAuthenticated() bool {
	return i.Authenticator.authenticated
}

type InstaUser struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	FullName        string `json:"full_name"`
	Bio             string `json:"bio"`
	HasPhoneNumber  bool   `json:"has_phone_number"`
	HasProfilePic   bool   `json:"has_profile_pic"`
	ProfilePicURL   string `json:"profile_pic_url"`
	ProfilePicURLHD string `json:"profile_pic_url_hd"`
	ProfAcc         bool   `json:"is_professional_account"`
	Private         bool   `json:"is_private"`
	NewAcc          bool   `json:"is_joined_recently"`
}

// GetMe returns the user information of the currently authenticated user.
func (i *Instagram) GetMe() (*InstaUser, error) {
	if !i.Authenticator.authenticated {
		return nil, fmt.Errorf("not authenticated")
	}

	req, _ := http.NewRequest("GET", "https://www.instagram.com", nil)
	resp, err := i.Authenticator.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get me failed: %s", resp.Status)
	}

	var user *InstaUser

	if matches := regexp.MustCompile(`{"raw":"(.*?)"},`).FindStringSubmatch(string(b)); len(matches) > 0 {
		match := strings.Split(strings.ReplaceAll(matches[1], "\\", ""), `badge_count":"`)[0] + `badge_count":"0"}}}`
		var sharedData struct {
			Config struct {
				Viewer InstaUser `json:"viewer"`
			} `json:"config"`
		}

		if err := json.Unmarshal([]byte(match), &sharedData); err != nil {
			return nil, err
		}

		user = &sharedData.Config.Viewer
	}

	return user, nil
}

type UserFull struct {
	Biography              string `json:"biography"`
	BioLinks               []any  `json:"bio_links"`
	ExternalURL            any    `json:"external_url"`
	ExternalURLLinkshimmed any    `json:"external_url_linkshimmed"`
	EdgeFollowedBy         struct {
		Count int `json:"count"`
	} `json:"edge_followed_by"`
	Fbid             string `json:"fbid"`
	FollowedByViewer bool   `json:"followed_by_viewer"`
	EdgeFollow       struct {
		Count int `json:"count"`
	} `json:"edge_follow"`
	FollowsViewer         bool   `json:"follows_viewer"`
	FullName              string `json:"full_name"`
	HasBlockedViewer      bool   `json:"has_blocked_viewer"`
	HighlightReelCount    int    `json:"highlight_reel_count"`
	ID                    string `json:"id"`
	IsBusinessAccount     bool   `json:"is_business_account"`
	IsProfessionalAccount bool   `json:"is_professional_account"`
	IsJoinedRecently      bool   `json:"is_joined_recently"`
	GuardianID            any    `json:"guardian_id"`
	IsPrivate             bool   `json:"is_private"`
	IsVerified            bool   `json:"is_verified"`
	EdgeMutualFollowedBy  struct {
		Count int   `json:"count"`
		Edges []any `json:"edges"`
	} `json:"edge_mutual_followed_by"`
	ProfilePicURL   string `json:"profile_pic_url"`
	ProfilePicURLHd string `json:"profile_pic_url_hd"`
	Username        string `json:"username"`
	ConnectedFbPage any    `json:"connected_fb_page"`
}

// GetProfile returns the user information of the given username.
func (i *Instagram) GetProfile(username string) (*UserFull, error) {
	if !i.Authenticator.authenticated {
		return nil, fmt.Errorf("not authenticated")
	}

	if username == "" {
		return nil, fmt.Errorf("username is empty")
	}

	username = strings.TrimPrefix(username, "@")

	if strings.HasPrefix(username, "https://instagram.com/") {
		username = username[22:]
		username = strings.Split(username, "/")[0]
	}

	req, _ := http.NewRequest("GET", "https://www.instagram.com/api/v1/users/web_profile_info/?username="+username, nil)
	resp, err := i.Authenticator.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get profile failed: %s", resp.Status)
	}

	var userRaw struct {
		Data struct {
			User UserFull `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &userRaw); err != nil {
		return nil, err
	}

	return &userRaw.Data.User, nil
}

// GetProfilePicture returns the profile picture of the given user.
func (i *Instagram) GetProfilePicture(username string) (string, error) {
	user, err := i.GetProfile(username)
	if err != nil {
		return "", err
	}

	return user.ProfilePicURLHd, nil
}

// call the given Api method by passing the logged in user's session
func (i *Instagram) Raw(req *http.Request) (*http.Response, error) {
	return i.Authenticator.Do(req)
}

var (
	MediaTypePost  = "p"
	MediaTypeReel  = "reel"
	MediaTypeStory = "story"
)

type Media struct {
	Music struct {
		ID        string `json:"id"`
		Thumbnail string `json:"thumbnail"`
		Title     string `json:"title"`
		Artist    string `json:"artist"`
	} `json:"music,omitempty"`
	Comments int `json:"comments"`
	Author   struct {
		ID            string `json:"id"`
		Username      string `json:"username"`
		ProfilePicURL string `json:"profile_pic_url"`
	} `json:"author,omitempty"`

	// TODO: add other fields
}

// GetMedia returns the media information of the given mediaId/postId/shortcode/URL.
func (i *Instagram) GetMedia(mediaId string, mediaType ...string) (*Media, error) {
	if !i.Authenticator.authenticated {
		return nil, fmt.Errorf("not authenticated")
	}

	if mediaId == "" {
		return nil, fmt.Errorf("mediaId is empty")
	}

	var mediaTypeStr string = MediaTypePost
	if len(mediaType) > 0 {
		mediaTypeStr = mediaType[0]
	}

	actualMedia := genMediaLocation(mediaId, mediaTypeStr)
	if actualMedia == "" {
		return nil, fmt.Errorf("invalid mediaId")
	}

	req, _ := http.NewRequest("GET", actualMedia, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36")
	for _, cookie := range i.Authenticator.cookies {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code error: %d %s", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	b, _ := doc.Find("body").Html()
	if matches := regexp.MustCompile(`{"media":(.*)}`).FindStringSubmatch(b); len(matches) > 0 {
		ioutil.WriteFile("media.json", []byte(matches[1]), 0644)
	} // TODO

	return nil, nil
}

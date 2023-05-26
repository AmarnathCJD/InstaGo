package main

import (
	"encoding/base64"
	"net/http"
	"strings"
)

func encodeToBase64(str string) string {
	return base64.URLEncoding.Strict().EncodeToString([]byte(str))
}

func decodeFromBase64(str string) string {
	decoded, _ := base64.URLEncoding.Strict().DecodeString(str)
	return string(decoded)
}

func getCookie(cookies []*http.Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}

	return ""
}

func genMediaLocation(media string, mediaType string) string {
	if strings.Contains(media, "instagram.com") {
		return media
	}

	if mediaType == MediaTypePost {
		return "https://www.instagram.com/p/" + media
	} else if mediaType == MediaTypeStory {
		return "https://www.instagram.com/stories/" + media
	} else if mediaType == MediaTypeReel {
		return "https://www.instagram.com/reel/" + media
	}

	return ""
}

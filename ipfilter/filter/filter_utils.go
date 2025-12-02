package ipfilter

import (
	"io"
	"net/http"
)

func FetchURL(githubMetaURL string) ([]byte, error) {
	resp, err := http.Get(githubMetaURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

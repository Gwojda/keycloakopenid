package discovery

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
)

func DocumentFromIssuer(issuer string) (*Document, error) {
	requestUrl, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}

	requestUrl.Path = path.Join(requestUrl.Path, ".well-known/openid-configuration")
	wellKnown := requestUrl.String()

	resp, err := http.Get(wellKnown)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	document := Document{
		RawData: string(body),
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	err = decoder.Decode(&document)
	if err != nil {
		return nil, err
	}

	return &document, nil
}

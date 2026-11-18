package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxResponseBytes bounds how much of a provider response is read.
const maxResponseBytes = 1 << 20

// statusError reports a non-200 response from a provider.
type statusError struct {
	status int
	body   string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("unexpected HTTP status %d: %s", e.status, e.body)
}

// getJSON fetches url and decodes its JSON body into out.
func getJSON(ctx context.Context, client *http.Client, url string, header http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for name, values := range header {
		req.Header[name] = values
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(body, 512))
		return &statusError{status: resp.StatusCode, body: string(snippet)}
	}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

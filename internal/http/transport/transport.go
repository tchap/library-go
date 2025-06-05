package transport

import "net/http"

type Transport struct {
	next      http.RoundTripper
	modifiers []RequestModifier
}

type RequestModifier func(*http.Request) error

func SetUserAgent(userAgent string) RequestModifier {
	return func(r *http.Request) error {
		r.Header.Set("User-Agent", userAgent)
		return nil
	}
}

func NewTransport(next http.RoundTripper, modifiers ...RequestModifier) http.RoundTripper {
	return &Transport{
		next:      next,
		modifiers: modifiers,
	}
}

func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	for _, modifier := range t.modifiers {
		if err = modifier(req); err != nil {
			return nil, err
		}
	}
	return t.next.RoundTrip(req)
}

package palisadeproxy_test

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/palisade-human-trust/palisade/pkg/palisadeproxy"
)

func Example() {
	upstreamURL, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
	adapter, err := palisadeproxy.New(palisadeproxy.Config{
		BaseURL:     "https://palisade.internal",
		APIKey:      "replace-with-a-secret",
		FailureMode: palisadeproxy.FailClosed,
		Upstream:    httputil.NewSingleHostReverseProxy(upstreamURL),
		Classifier:  palisadeproxy.StaticClassification("read", "public_content"),
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = http.ListenAndServe("127.0.0.1:8081", adapter)
}

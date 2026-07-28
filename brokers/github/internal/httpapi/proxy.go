package httpapi

import (
	"io"
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/transport/http"
)

func (s *Server) proxyTo(c echo.Context, upstreamURL *url.URL, configure func(*http.Request) error) error {
	request, err := http.NewRequestWithContext(
		c.Request().Context(),
		c.Request().Method,
		upstreamURL.String(),
		c.Request().Body,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "create upstream github request")
	}
	httpx.CopyHeaders(request.Header, c.Request().Header, httpx.ProxyRequestHeader)
	if err := configure(request); err != nil {
		return err
	}
	return s.doProxy(c, request)
}

func (s *Server) doProxy(c echo.Context, request *http.Request) error {
	// #nosec G704 -- upstream URLs are built from fixed GitHub base URLs and policy-gated route params.
	markUpstreamDispatched(c)
	response, err := s.githubGitClient.Do(request)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "upstream github request failed")
	}
	defer func() {
		_ = response.Body.Close()
	}()
	httpx.CopyHeaders(c.Response().Header(), response.Header, githubProxyResponseHeader)
	c.Response().WriteHeader(response.StatusCode)
	_, err = io.Copy(c.Response(), response.Body)
	return err
}

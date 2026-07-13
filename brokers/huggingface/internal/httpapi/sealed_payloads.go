package httpapi

import (
	"github.com/labstack/echo/v4"
)

func (s *Server) uploadSealedPayload(c echo.Context) error { return s.sealedPayloads.Upload(c) }

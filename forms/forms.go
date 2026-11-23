package forms

import (
	"errors"
	"mime/multipart"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/antonybholmes/go-sys/log"
	"github.com/gin-gonic/gin"
)

type (
	FormParser struct {
		maxBody int64
	}

	FormFile struct {
		File        multipart.File
		Filename    string
		ContentType string
		Size        int64
	}
)

func NewFormParser(maxBody int64) *FormParser {
	return &FormParser{maxBody: maxBody}
}

func (h *FormParser) GetFormFile(c *gin.Context, field string) (*FormFile, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.maxBody)

	file, fileHeader, err := c.Request.FormFile(field)

	// clean up but seems unnecessary if no multipart form was created
	if c.Request.MultipartForm != nil {
		defer func() {
			if err := c.Request.MultipartForm.RemoveAll(); err != nil {
				log.Error().Msgf("remove multipart temporary files: %v", err)
			}
		}()
	}

	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, errors.New("request body too large")
		} else {
			return nil, errors.New("a multipart file field named " + field + " is required")
		}
	}

	contentType := fileHeader.Header.Get("Content-Type")

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if !ValidMetadata(fileHeader.Filename, 1024) || !ValidMetadata(contentType, 255) {
		return nil, errors.New("invalid file metadata")
	}

	return &FormFile{
		File:        file,
		Filename:    fileHeader.Filename,
		ContentType: contentType,
		Size:        fileHeader.Size,
	}, nil
}

func ValidMetadata(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

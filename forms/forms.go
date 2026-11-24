package forms

import (
	"errors"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

type (
	FormParser struct {
		maxBody int64
	}

	FormFile struct {
		Content     multipart.File
		Filename    string
		ContentType string
		Size        int64
		// Cleanup
		Close func() error
	}
)

func NewFormParser(maxBody int64) *FormParser {
	return &FormParser{maxBody: maxBody}
}

// Get all files with same name, e.g. images
func (h *FormParser) GetFormFileGroup(c *gin.Context, field string) ([]*FormFile, func(), error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.maxBody)

	form, err := c.MultipartForm()

	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, nil, errors.New("request body too large")
		}
		return nil, nil, errors.New("a multipart file field named " + field + " is required")

	}

	files := form.File[field]

	if len(files) == 0 {
		_ = form.RemoveAll()
		return nil, nil, errors.New("a multipart file field named " + field + " is required")
	}

	formFiles := make([]*FormFile, 0, len(files))

	for _, file := range files {
		contentType := file.Header.Get("Content-Type")

		if contentType == "" {
			contentType = "application/octet-stream"
		}

		if !ValidMetadata(file.Filename, 1024) || !ValidMetadata(contentType, 255) {
			form.RemoveAll()
			return nil, nil, errors.New("invalid file metadata")
		}

		openedFile, err := file.Open()

		if err != nil {
			form.RemoveAll()
			return nil, nil, err
		}

		formFiles = append(formFiles, &FormFile{
			Content:     openedFile,
			Filename:    filepath.Base(file.Filename),
			ContentType: contentType,
			Size:        file.Size,
		})
	}

	// Helper to close any opened files and remove temp disk files
	cleanup := func() {
		for _, ff := range formFiles {
			if ff.Content != nil {
				_ = ff.Content.Close()
			}
		}
		_ = form.RemoveAll()
	}

	return formFiles, cleanup, nil
}

func (h *FormParser) GetFormFile(c *gin.Context, field string) (*FormFile, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.maxBody)

	file, err := c.FormFile(field)

	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, errors.New("request body too large")
		} else {
			return nil, errors.New("a multipart file field named " + field + " is required")
		}
	}

	// // clean up but seems unnecessary if no multipart form was created
	// if c.Request.MultipartForm != nil {
	// 	defer func() {
	// 		if err := c.Request.MultipartForm.RemoveAll(); err != nil {
	// 			log.Error().Msgf("remove multipart temporary files: %v", err)
	// 		}
	// 	}()
	// }

	contentType := file.Header.Get("Content-Type")

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if !ValidMetadata(file.Filename, 1024) || !ValidMetadata(contentType, 255) {
		return nil, errors.New("invalid file metadata")
	}

	cleanup := func() error {
		if c.Request.MultipartForm != nil {
			return c.Request.MultipartForm.RemoveAll()
		}
		return nil
	}

	content, err := file.Open()

	if err != nil {
		_ = cleanup()
		return nil, err
	}

	return &FormFile{
		Content:     content,
		Filename:    filepath.Base(file.Filename),
		ContentType: contentType,
		Size:        file.Size,
		Close:       cleanup,
	}, nil
}

// GetFormFiles returns the requested multipart files in the order of the field names.
func (h *FormParser) GetFormFiles(c *gin.Context, fields ...string) ([]*FormFile, error) {
	formFiles := make([]*FormFile, 0, len(fields))

	for _, field := range fields {
		formFile, err := h.GetFormFile(c, field)
		if err != nil {
			return nil, err
		}

		formFiles = append(formFiles, formFile)
	}

	return formFiles, nil
}

// GetFormFileMap returns the requested multipart files keyed by field name.
func (h *FormParser) GetFormFileMap(c *gin.Context, fields ...string) (map[string]*FormFile, error) {
	fileMap := make(map[string]*FormFile, len(fields))

	for _, field := range fields {
		formFile, err := h.GetFormFile(c, field)
		if err != nil {
			return nil, err
		}

		fileMap[field] = formFile
	}

	return fileMap, nil
}

func ValidMetadata(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

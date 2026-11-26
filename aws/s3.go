package aws

import (
	awssys "github.com/antonybholmes/go-sys/aws"
	"github.com/antonybholmes/go-web"
	"github.com/gin-gonic/gin"
)

type (
	S3WebStore struct {
		s3Store *awssys.S3Store
	}
)

func NewS3WebStore(s3Store *awssys.S3Store) *S3WebStore {
	return &S3WebStore{
		s3Store: s3Store,
	}
}

// DownloadZip streams the specified S3 objects as a ZIP archive to the client.
func (s *S3WebStore) DownloadZip(c *gin.Context, keys []string, filename string) {
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)

	ctx := c.Request.Context()

	if err := s.s3Store.DownloadZip(ctx, keys, c.Writer); err != nil {
		web.InternalErrorResp(c, err)
	}
}

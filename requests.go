package web

import "github.com/gin-gonic/gin"

type (
	ReqIdsParams struct {
		Ids []string `json:"ids"`
	}
)

func ParseIdParamsFromPost(c *gin.Context) (*ReqIdsParams, error) {

	var params ReqIdsParams

	err := c.Bind(&params)

	if err != nil {
		return nil, err
	}

	return &params, nil
}

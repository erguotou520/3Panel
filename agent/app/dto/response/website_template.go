package response

import (
	"github.com/3panel-dev/3panel/agent/app/model"
)

type WebsiteTemplateDTO struct {
	model.WebsiteTemplate
}

type WebsiteTemplateOutputDTO struct {
	model.WebsiteTemplateOutput
	TemplateName string `json:"templateName"`
}

type WebsitePreviewDTO struct {
	HTML string `json:"html"`
}

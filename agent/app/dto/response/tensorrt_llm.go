package response

import (
	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
)

type TensorRTLLMsRes struct {
	Items []TensorRTLLMDTO `json:"items"`
	Total int64            `json:"total"`
}

type TensorRTLLMDTO struct {
	model.TensorRTLLM
	Version  string `json:"version"`
	Model    string `json:"model"`
	Dir      string `json:"dir"`
	ModelDir string `json:"modelDir"`
	Image    string `json:"image"`
	Command  string `json:"command"`

	ExposedPorts []request.ExposedPort `json:"exposedPorts"`
	Environments []request.Environment `json:"environments"`
	Volumes      []request.Volume      `json:"volumes"`
}

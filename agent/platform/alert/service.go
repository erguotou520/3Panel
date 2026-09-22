package alert

import (
	"net/http"

	"github.com/3panel-dev/3panel/agent/app/dto"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/constant"
	alertUtil "github.com/3panel-dev/3panel/agent/utils/alert"
	multinode "github.com/3panel-dev/3panel/agent/platform/multinode"
)

type alertHelper struct{}

var (
	_ CustomWebhookTester           = (*alertHelper)(nil)
	_ CustomWebhookDeliveryProvider = (*alertHelper)(nil)
)

var loadCommunityCustomWebhookContext = func() (*http.Transport, *dto.AgentInfo) {
	agentInfo, _ := multinode.Provider.GetAgentInfo()
	return multinode.Provider.LoadRequestTransport(), agentInfo
}

func NewProvider() AlertProvider {
	return &alertHelper{}
}

func (a *alertHelper) CreateTaskScanSMSAlertLog(alert dto.AlertDTO, alertType string, create dto.AlertLogCreate, pushAlert dto.PushAlert, config model.AlertConfig, method string) error {
	return nil
}

func (a *alertHelper) CreateSMSAlertLog(alertType string, info dto.AlertDTO, create dto.AlertLogCreate, project string, params []dto.Param, config model.AlertConfig, method string) error {
	return nil
}

func (a *alertHelper) CreateTaskScanWebhookAlertLog(alert dto.AlertDTO, alertType string, create dto.AlertLogCreate, pushAlert dto.PushAlert, config model.AlertConfig, transport *http.Transport, agentInfo *dto.AgentInfo) error {
	if config.Type == constant.Custom {
		return alertUtil.CreateTaskScanCustomWebhookAlertLog(alert, alertType, create, pushAlert, config, transport, agentInfo)
	}
	return nil
}

func (a *alertHelper) CreateWebhookAlertLog(alertType string, info dto.AlertDTO, create dto.AlertLogCreate, project string, params []dto.Param, config model.AlertConfig, transport *http.Transport, agentInfo *dto.AgentInfo) error {
	if config.Type == constant.Custom {
		return alertUtil.CreateCustomWebhookAlertLog(alertType, info, create, project, params, config, transport, agentInfo)
	}
	return nil
}

func (a *alertHelper) CreateCustomWebhookAlertLog(alertType string, info dto.AlertDTO, create dto.AlertLogCreate, project string, params []dto.Param, config model.AlertConfig, transport *http.Transport, agentInfo *dto.AgentInfo, _ dto.AlertTaskMetadata) (DeliveryResult, error) {
	err := alertUtil.CreateCustomWebhookAlertLog(alertType, info, create, project, params, config, transport, agentInfo)
	return DeliveryResult{}, err
}

func (a *alertHelper) CreateTaskScanCustomWebhookAlertLog(alert dto.AlertDTO, alertType string, create dto.AlertLogCreate, pushAlert dto.PushAlert, config model.AlertConfig, transport *http.Transport, agentInfo *dto.AgentInfo, _ dto.AlertTaskMetadata) (DeliveryResult, error) {
	err := alertUtil.CreateTaskScanCustomWebhookAlertLog(alert, alertType, create, pushAlert, config, transport, agentInfo)
	return DeliveryResult{}, err
}

func (a *alertHelper) TestCustomWebhook(config dto.AlertCustomWebhookResolvedConfig) (dto.AlertConfigTestResult, error) {
	transport, agentInfo := loadCommunityCustomWebhookContext()
	return alertUtil.TestCustomWebhook(config, transport, agentInfo)
}

func (a *alertHelper) GetLicenseErrorAlert() (uint, error) {
	return 0, nil
}

func (a *alertHelper) GetNodeErrorAlert() (uint, error) {
	return 0, nil
}

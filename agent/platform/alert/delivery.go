package alert

import (
	"fmt"
	"net/http"

	"github.com/3panel-dev/3panel/agent/app/dto"
	"github.com/3panel-dev/3panel/agent/app/model"
)

func DeliverCustomWebhookAlertLog(
	alertType string,
	info dto.AlertDTO,
	create dto.AlertLogCreate,
	project string,
	params []dto.Param,
	config model.AlertConfig,
	transport *http.Transport,
	agentInfo *dto.AgentInfo,
	task dto.AlertTaskMetadata,
) (DeliveryResult, error) {
	if provider, ok := Provider.(CustomWebhookDeliveryProvider); ok {
		result, err := provider.CreateCustomWebhookAlertLog(alertType, info, create, project, params, config, transport, agentInfo, task)
		return validateCustomWebhookDeliveryResult(result, err)
	}
	err := Provider.CreateWebhookAlertLog(alertType, info, create, project, params, config, transport, agentInfo)
	return DeliveryResult{}, err
}

func DeliverTaskScanCustomWebhookAlertLog(
	alert dto.AlertDTO,
	alertType string,
	create dto.AlertLogCreate,
	pushAlert dto.PushAlert,
	config model.AlertConfig,
	transport *http.Transport,
	agentInfo *dto.AgentInfo,
	task dto.AlertTaskMetadata,
) (DeliveryResult, error) {
	if provider, ok := Provider.(CustomWebhookDeliveryProvider); ok {
		result, err := provider.CreateTaskScanCustomWebhookAlertLog(alert, alertType, create, pushAlert, config, transport, agentInfo, task)
		return validateCustomWebhookDeliveryResult(result, err)
	}
	err := Provider.CreateTaskScanWebhookAlertLog(alert, alertType, create, pushAlert, config, transport, agentInfo)
	return DeliveryResult{}, err
}

func validateCustomWebhookDeliveryResult(result DeliveryResult, err error) (DeliveryResult, error) {
	if err != nil {
		return result, err
	}
	if result.Queued && result.LogID == 0 {
		return DeliveryResult{}, fmt.Errorf("custom webhook provider queued a delivery without a log ID")
	}
	return result, nil
}

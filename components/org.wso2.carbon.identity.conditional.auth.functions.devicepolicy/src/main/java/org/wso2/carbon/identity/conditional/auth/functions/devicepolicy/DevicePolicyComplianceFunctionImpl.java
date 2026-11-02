/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.devicepolicy;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsWrapperFactoryProvider;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseParameters;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.conditional.auth.functions.devicepolicy.internal.DevicePolicyFunctionsServiceHolder;
import org.wso2.carbon.identity.device.policy.api.constant.DevicePolicyErrorMessage;
import org.wso2.carbon.identity.device.policy.api.exception.DevicePolicyClientException;
import org.wso2.carbon.identity.device.policy.api.exception.DevicePolicyException;
import org.wso2.carbon.identity.device.policy.api.model.DevicePolicyEvaluationResult;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link DevicePolicyComplianceFunction}. The verified device payload
 * is captured and stored on the authentication context at initiation (see the device.policy
 * component's {@code DeviceDataResolverImpl}); this function reads it from the context under
 * {@link FrameworkConstants#DEVICE_DATA}.
 */
public class DevicePolicyComplianceFunctionImpl implements DevicePolicyComplianceFunction {

    private static final Log LOG = LogFactory.getLog(DevicePolicyComplianceFunctionImpl.class);

    private static final String COMPONENT_ID = "adaptive-auth-service";
    private static final String ACTION_EVALUATE_POLICY = "evaluate-device-policy";
    private static final String PARAM_POLICY_NAME = "policyName";
    private static final String UNKNOWN = "unknown";

    private static final String COMPLIANT = "compliant";
    private static final String STATUS = "status";
    private static final String FAILED_FIELDS = "failedFields";
    private static final String MISSING_FIELDS = "missingFields";
    private static final String ERROR_CODE = "errorCode";
    private static final String STATUS_ERROR = "ERROR";

    static final String ERROR_DEVICE_DATA_UNAVAILABLE = "device_data_unavailable";
    static final String ERROR_POLICY_NOT_FOUND = "policy_not_found";
    static final String ERROR_POLICY_ERROR = "policy_error";
    static final String ERROR_EVALUATION_ERROR = "evaluation_error";

    @Override
    @HostAccess.Export
    public JsBaseParameters evaluate(JsBaseAuthenticationContext context, String policyName) {

        try {
            String tenantDomain = context.getWrapped().getTenantDomain();

            Object data = context.getWrapped().getProperty(FrameworkConstants.DEVICE_DATA);
            if (!(data instanceof Map)) {
                logMissingDeviceData(policyName);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No device data on the authentication context for policy: " + policyName);
                }
                return buildErrorResult(ERROR_DEVICE_DATA_UNAVAILABLE);
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> deviceData = new HashMap<>((Map<String, Object>) data);

            String appId = context.getWrapped().getServiceProviderResourceId();

            DevicePolicyEvaluationResult result = DevicePolicyFunctionsServiceHolder.getInstance()
                    .getDevicePolicyEvaluator()
                    .evaluateByPolicyName(policyName, deviceData, appId, tenantDomain);

            return buildResult(result);
        } catch (DevicePolicyClientException e) {
            if (DevicePolicyErrorMessage.ERROR_DEVICE_POLICY_NOT_FOUND.getCode().equals(e.getErrorCode())) {
                LOG.warn("Device policy not found: " + policyName);
                return buildErrorResult(ERROR_POLICY_NOT_FOUND);
            }
            LOG.warn("Error while evaluating device policy: " + policyName, e);
            return buildErrorResult(ERROR_POLICY_ERROR);
        } catch (DevicePolicyException e) {
            LOG.error("Error while evaluating device policy: " + policyName, e);
            return buildErrorResult(ERROR_EVALUATION_ERROR);
        }
    }

    /**
     * Build the script facing result for a completed policy evaluation. Only a {@code COMPLIANT} status is
     * reported as compliant, so any unrecognized status fails closed.
     *
     * @param result Evaluation result returned by the device policy evaluator.
     * @return Evaluation result object exposed to the script.
     */
    private JsBaseParameters buildResult(DevicePolicyEvaluationResult result) {

        DevicePolicyEvaluationResult.Status status = result.getStatus();
        Map<String, Object> resultData = new HashMap<>();
        resultData.put(COMPLIANT, status == DevicePolicyEvaluationResult.Status.COMPLIANT);
        resultData.put(STATUS, status != null ? status.name() : STATUS_ERROR);
        resultData.put(FAILED_FIELDS, new ArrayList<>(result.getFailedFields()));
        resultData.put(MISSING_FIELDS, new ArrayList<>(result.getMissingFields()));
        return toJsParameters(resultData);
    }

    /**
     * Build the script facing result for a policy evaluation that could not be performed.
     *
     * @param errorCode Code describing why the evaluation could not be performed.
     * @return Non compliant evaluation result object exposed to the script.
     */
    private JsBaseParameters buildErrorResult(String errorCode) {

        Map<String, Object> resultData = new HashMap<>();
        resultData.put(COMPLIANT, false);
        resultData.put(STATUS, STATUS_ERROR);
        resultData.put(FAILED_FIELDS, new ArrayList<String>());
        resultData.put(MISSING_FIELDS, new ArrayList<String>());
        resultData.put(ERROR_CODE, errorCode);
        return toJsParameters(resultData);
    }

    private JsBaseParameters toJsParameters(Map<String, Object> resultData) {

        return JsWrapperFactoryProvider.getInstance().getWrapperFactory().createJsParameters(resultData);
    }

    /**
     * Log that no verified device data was present on the authentication context for a policy check.
     *
     * @param policyName Policy that could not be evaluated.
     */
    private void logMissingDeviceData(String policyName) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder builder =
                new DiagnosticLog.DiagnosticLogBuilder(COMPONENT_ID, ACTION_EVALUATE_POLICY);
        builder.resultMessage("No verified device data on the authentication context; device policy cannot be "
                        + "evaluated.")
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                .inputParam(PARAM_POLICY_NAME, policyName != null ? policyName : UNKNOWN);
        LoggerUtils.triggerDiagnosticLogEvent(builder);
    }
}

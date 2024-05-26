/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.Collections;
import java.util.Map;

/**
 * Function to update user password.
 */
public class UpdateUserPasswordFunctionImpl implements UpdateUserPasswordFunction {

    private static final Log LOG = LogFactory.getLog(UpdateUserPasswordFunctionImpl.class);

    @Override
    @HostAccess.Export
    public void updateUserPassword(JsAuthenticatedUser user, Object... parameters) {

        if (user == null) {
            throw new IllegalArgumentException("User is not defined.");
        }
        if (parameters == null || parameters.length == 0) {
            throw new IllegalArgumentException("Password is not defined.");
        }

        String newPassword = null;
        Map<String, Object> eventHandlers = null;

        if (parameters.length == 2) {
            LOG.debug("Both password and event handlers are provided.");
            newPassword = (String) parameters[0];

            if (parameters[1] instanceof Map) {
                eventHandlers = (Map<String, Object>) parameters[1];
            } else {
                throw new IllegalArgumentException("Invalid argument type. Expected eventHandlers " +
                        "(Map<String, Object>).");
            }
        } else {
            LOG.debug("Only the password is provided.");
            newPassword = (String) parameters[0];
        }

        if (StringUtils.isBlank(newPassword)) {
            throw new IllegalArgumentException("The provided password is empty.");
        }

        if (eventHandlers != null) {
            String finalNewPassword = newPassword;
            AsyncProcess asyncProcess = new AsyncProcess((context, asyncReturn) -> {
                try {
                    doUpdatePassword(user, finalNewPassword);
                    asyncReturn.accept(context, Collections.emptyMap(), Constants.OUTCOME_SUCCESS);
                } catch (FrameworkException e) {
                    asyncReturn.accept(context, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                }
            });
            JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
        } else {
            try {
                doUpdatePassword(user, newPassword);
            } catch (FrameworkException e) {
                // Ignore FrameworkException as the function is not expected to throw any.
            }
        }
    }

    private void doUpdatePassword(JsAuthenticatedUser user, String newPassword) throws FrameworkException {

        try {
            if (user.getWrapped() != null) {
                String tenantDomain = user.getWrapped().getTenantDomain();
                String userStoreDomain = user.getWrapped().getUserStoreDomain();
                String username = user.getWrapped().getUserName();
                String loggableUserId = user.getWrapped().getLoggableMaskedUserId();
                UserRealm userRealm = Utils.getUserRealm(tenantDomain);

                if (userRealm != null) {
                    UserStoreManager userStoreManager = Utils.getUserStoreManager(
                            tenantDomain, userRealm, userStoreDomain);

                    // Update the user password.
                    userStoreManager.updateCredentialByAdmin(username, newPassword);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("User password updated successfully for the user: %s " +
                                "in tenant: %s.", username, tenantDomain));
                    }
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                                new DiagnosticLog.DiagnosticLogBuilder(
                                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                                        Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                                );
                        diagnosticLogBuilder.resultMessage("User password updated successfully.")
                                .inputParam("user", loggableUserId)
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("Unable to find user realm for the user: %s " +
                                "in tenant: %s", username, tenantDomain));
                    }
                    String message = "Unable to find user realm for the user.";
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                                new DiagnosticLog.DiagnosticLogBuilder(
                                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                                        Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                                );
                        diagnosticLogBuilder.resultMessage(message)
                                .inputParam("user", loggableUserId)
                                .inputParam("tenantDomain", tenantDomain)
                                .inputParam("userStoreDomain", userStoreDomain)
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }

                    throw new FrameworkException(message);
                }
            } else {
                String message = "Unable to get wrapped content for the user.";

                LOG.debug(message);
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                    );
                    diagnosticLogBuilder.resultMessage(message)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }

                throw new FrameworkException(message);
            }
        } catch (UserStoreException | FrameworkException e) {
            String message = "Error occurred while updating the user password.";

            LOG.error(message, e);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                );
                diagnosticLogBuilder.resultMessage(message)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }

            throw new FrameworkException(message, e);
        }
    }
}

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
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.DiagnosticLog;

/**
 * Function to update user password.
 */
public class UpdateUserPasswordFunctionImpl implements UpdateUserPasswordFunction {

    private static final Log LOG = LogFactory.getLog(UpdateUserPasswordFunctionImpl.class);

    @Override
    public void updateUserPassword(JsAuthenticatedUser user, Object... parameters) {

        if (user == null) {
            LOG.debug("User is not defined.");
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS
                );
                diagnosticLogBuilder.resultMessage("User is not defined.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }

            return;
        }
        if (parameters == null || parameters.length == 0) {
            LOG.debug("Password parameters are not defined.");
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS
                );
                diagnosticLogBuilder.resultMessage("Password parameters are not defined.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }

            return;
        }

        String newPassword = null;
        String passwordMigrationStatusClaim = null;

        if (parameters.length == 2) {
            LOG.debug("Both password and password migration status claim parameters are provided.");
            newPassword = (String) parameters[0];
            passwordMigrationStatusClaim = (String) parameters[1];
        } else {
            LOG.debug("Only the new password is provided.");
            newPassword = (String) parameters[0];
        }

        if (StringUtils.isBlank(newPassword)) {
            LOG.debug("The provided password is empty.");
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS
                );
                diagnosticLogBuilder.resultMessage("The provided password is empty.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }

            return;
        }

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

                    if (userStoreManager == null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(String.format("Unable to find user store manager for the " +
                                    "user store domain: %s in tenant: %s", userStoreDomain, tenantDomain));
                        }
                        if (LoggerUtils.isDiagnosticLogsEnabled()) {
                            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                                    new DiagnosticLog.DiagnosticLogBuilder(
                                            Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                                            Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                                    );
                            diagnosticLogBuilder.resultMessage("Unable to find user store manager for the " +
                                            "user store domain.")
                                    .inputParam("tenantDomain", tenantDomain)
                                    .inputParam("userStoreDomain", userStoreDomain)
                                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }

                        return;
                    }

                    // Check for password migration status only if the claim is present.
                    if (StringUtils.isNotBlank(passwordMigrationStatusClaim)) {
                        String passwordMigrationStatus = userStoreManager.getUserClaimValue(
                                username, passwordMigrationStatusClaim, null);

                        if (LOG.isDebugEnabled()) {
                            LOG.debug(String.format("Password migration status for the user: %s in tenant: %s is: %s",
                                    username, tenantDomain, passwordMigrationStatus));
                        }

                        if (Boolean.parseBoolean(passwordMigrationStatus)) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug(String.format("Password migration has already been completed for the " +
                                        "user: %s in tenant: %s", username, tenantDomain));
                            }
                            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                                        new DiagnosticLog.DiagnosticLogBuilder(
                                                Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                                                Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                                        );
                                diagnosticLogBuilder.resultMessage("Password migration has already been completed " +
                                                "for the user.").inputParam("user", loggableUserId)
                                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                            }

                            return;
                        }
                    }

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

                    // Update the password migration status claim.
                    if (StringUtils.isNotBlank(passwordMigrationStatusClaim)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(String.format("Updating the password migration status claim: %s " +
                                    "for the user: %s in tenant: %s to true.",
                                    passwordMigrationStatusClaim, username, tenantDomain));
                        }
                        userStoreManager.setUserClaimValue(username, passwordMigrationStatusClaim, "true", null);

                        LOG.debug("Password migration status claim updated successfully for the user: " + username
                                + " in tenant: " + tenantDomain + ".");
                        if (LoggerUtils.isDiagnosticLogsEnabled()) {
                            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                                    new DiagnosticLog.DiagnosticLogBuilder(
                                            Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                                            Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                                    );
                            diagnosticLogBuilder.resultMessage("Password migration status claim updated successfully.")
                                    .inputParam("user", loggableUserId)
                                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("Unable to find user realm for the user: %s " +
                                "in tenant: %s", username, tenantDomain));
                    }
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                                new DiagnosticLog.DiagnosticLogBuilder(
                                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                                        Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                                );
                        diagnosticLogBuilder.resultMessage("Unable to find user realm for the user.")
                                .inputParam("user", loggableUserId)
                                .inputParam("tenantDomain", tenantDomain)
                                .inputParam("userStoreDomain", userStoreDomain)
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                }
            } else {
                LOG.debug("Unable to get wrapped content for the user.");
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                    );
                    diagnosticLogBuilder.resultMessage("Unable to get wrapped content for the user.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            }
        } catch (UserStoreException | FrameworkException e) {
            LOG.error("Error occurred while updating the user password.", e);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD
                );
                diagnosticLogBuilder.resultMessage("Error occurred while updating the user password.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        }
    }
}

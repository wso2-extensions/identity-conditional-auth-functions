/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.conditional.auth.functions.common.utils;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.secret.mgt.core.exception.SecretManagementException;
import org.wso2.carbon.identity.secret.mgt.core.model.ResolvedSecret;

public class CommonUtils {

    private static final String SECRET_TYPE_CALL_CHOREO = "ADAPTIVE_AUTH_CALL_CHOREO";
    private static final String SECRET_PREFIX = "secrets.";

    public static String getConnectorConfig(String key, String tenantDomain) throws IdentityEventException {

        //TODO check whether there is a more optimized way
        try {
            Property[] connectorConfigs;
            IdentityGovernanceService identityGovernanceService = FunctionsDataHolder.getInstance()
                    .getIdentityGovernanceService();
            if (identityGovernanceService != null) {
                connectorConfigs = identityGovernanceService.getConfiguration(new String[]{key}, tenantDomain);
                if (connectorConfigs != null && connectorConfigs.length > 0) {
                    return connectorConfigs[0].getValue();
                }
            }
            return null;
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while getting connector configurations for property :" + key, e);
        }
    }

    /**
     * Check whether the given value is a secret alias.
     *
     * @param value Value to check
     * @return True if the value is a secret alias, false otherwise
     */
    public static boolean isSecretAlias(String value) {

        return value.startsWith(SECRET_PREFIX);
    }

    /**
     * Resolve the secret alias to its actual value.
     *
     * @param alias Secret alias
     * @return Actual secret value
     */
    public static String resolveSecretFromAlias(String alias) {

        return alias.substring(SECRET_PREFIX.length());
    }

    /**
     * Resolves the secret value, whether the input is a direct secret name or an alias.
     * If the input is an alias, it first resolves the alias to the actual secret name and then fetches the secret value.
     * If the input is not an alias, it returns the input directly, assuming it's already the resolved secret.
     *
     * @param secretOrAlias The secret name or alias.
     * @return The input itself if it's not an alias, or the resolved secret value if it is an alias.
     * @throws SecretManagementException If there is an error in resolving the secret from an alias.
     */
    public static String getResolvedSecret(String secretOrAlias) throws SecretManagementException {
        if (StringUtils.isNotEmpty(secretOrAlias)) {
            if (!isSecretAlias(secretOrAlias)) {
                // If it's not an alias, return the input directly
                return secretOrAlias;
            } else {
                // If it's an alias, strip the prefix to get the actual secret name and resolve it
                String secretName = secretOrAlias.substring(SECRET_PREFIX.length());
                ResolvedSecret responseDTO = FunctionsDataHolder.getInstance().getSecretConfigManager()
                        .getResolvedSecret(SECRET_TYPE_CALL_CHOREO, secretName);
                if (responseDTO != null) {
                    return responseDTO.getResolvedSecretValue();
                }
            }
        }
        return null;
    }
}

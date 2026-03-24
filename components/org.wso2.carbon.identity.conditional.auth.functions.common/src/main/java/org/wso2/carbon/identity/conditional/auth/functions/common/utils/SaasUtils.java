/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.common.utils;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * Utility methods for SaaS application checks in adaptive authentication functions.
 */
public class SaasUtils {

    private static final Log LOG = LogFactory.getLog(SaasUtils.class);

    private SaasUtils() {
    }

    /**
     * Determines if the application associated with the current authentication flow is a SaaS application.
     *
     * @param context AuthenticationContext of the current authentication flow.
     * @return true if the application is a SaaS app, false otherwise.
     */
    public static boolean isSaasApp(AuthenticationContext context) {

        if (context == null || context.getSequenceConfig() == null
                || context.getSequenceConfig().getApplicationConfig() == null
                || context.getSequenceConfig().getApplicationConfig().getServiceProvider() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to determine if the application is a SaaS app. Treating as non-SaaS app.");
            }
            return false;
        }
        return context.getSequenceConfig().getApplicationConfig().getServiceProvider().isSaasApp();
    }

    /**
     * Checks if cross-tenant operations for SaaS applications are enabled in the global identity configuration.
     * Defaults to false when the property is absent.
     *
     * @return true if cross-tenant operations are enabled for SaaS apps.
     */
    public static boolean isSaaSCrossTenantOperationsEnabled() {

        String value = IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS);
        if (StringUtils.isBlank(value)) {
            return false;
        }
        return Boolean.parseBoolean(value);
    }
}

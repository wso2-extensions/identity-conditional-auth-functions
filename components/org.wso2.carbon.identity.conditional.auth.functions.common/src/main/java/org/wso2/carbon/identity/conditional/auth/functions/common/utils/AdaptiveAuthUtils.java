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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * Utility methods shared across adaptive authentication function implementations.
 */
public class AdaptiveAuthUtils {

    private static final Log LOG = LogFactory.getLog(AdaptiveAuthUtils.class);

    private AdaptiveAuthUtils() {
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

    /**
     * Check whether the user belongs to the SP tenant domain.
     *
     * When tenant-qualified URLs are enabled, the Tomcat valve sets the correct tenant on
     * PrivilegedCarbonContext from the URL path so that context is authoritative.
     * When tenant-qualified URLs are disabled, PrivilegedCarbonContext always returns carbon.super
     * during adaptive script execution, so the SP tenant domain from AuthenticationContext is used instead.
     * Returns false if context is null.
     *
     * @param userTenantDomain Tenant domain of the user.
     * @param context          AuthenticationContext of the current authentication flow.
     * @return true if the user belongs to the SP tenant domain. Else false.
     */
    public static boolean isUserInCurrentTenant(String userTenantDomain, AuthenticationContext context) {

        if (isSaasApp(context) && isSaaSCrossTenantOperationsEnabled()) {
            return true;
        }

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return StringUtils.equals(userTenantDomain,
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
        }

        if (context == null || StringUtils.isBlank(context.getTenantDomain())) {
            LOG.warn("Unable to determine the tenant domain from the authentication context. " +
                    "Hence user tenant domain validation is considered as failed.");
            return false;
        }
        return StringUtils.equals(userTenantDomain, context.getTenantDomain());
    }
}

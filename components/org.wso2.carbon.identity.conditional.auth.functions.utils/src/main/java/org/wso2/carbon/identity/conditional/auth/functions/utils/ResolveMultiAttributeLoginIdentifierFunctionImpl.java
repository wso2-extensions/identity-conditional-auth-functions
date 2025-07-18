/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;

/**
 * Function to resolve user from multi attribute login identifier.
 */
public class ResolveMultiAttributeLoginIdentifierFunctionImpl implements ResolveMultiAttributeLoginIdentifierFunction {

    private static final Log log = LogFactory.getLog(ResolveMultiAttributeLoginIdentifierFunctionImpl.class);

    @Override
    @HostAccess.Export
    public String resolveMultiAttributeLoginIdentifier(String loginIdentifier, String tenantDomain) {

        if (!IdentityTenantUtil.resolveTenantDomain().equals(tenantDomain)) {
            log.debug("Cross-tenant multi attribute login identifier lookup is not allowed.");
            return null;
        }
        ResolvedUserResult resolvedUserResult = FrameworkUtils.processMultiAttributeLoginIdentification(
                loginIdentifier, tenantDomain);

        if (resolvedUserResult != null &&
                ResolvedUserResult.UserResolvedStatus.SUCCESS.equals(resolvedUserResult.getResolvedStatus())) {
            return resolvedUserResult.getUser().getPreferredUsername();
        }
        return null;
    }
}

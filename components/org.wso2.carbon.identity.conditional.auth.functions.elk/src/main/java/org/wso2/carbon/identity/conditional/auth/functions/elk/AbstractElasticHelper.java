/*
 *  Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.elk;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.HttpPost;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.AuthenticationFactory;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.AuthenticationManager;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.UsernamePasswordCredentials;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.event.IdentityEventException;

/**
 * Abstract class for handling http calls.
 */
public abstract class AbstractElasticHelper {

    private static final Log LOG = LogFactory.getLog(AbstractElasticHelper.class);

    protected AuthenticationFactory authenticationFactory = new AuthenticationFactory();

    public AbstractElasticHelper() {

    }

    protected void handleAuthentication(HttpPost request, String tenantDomain) throws IdentityEventException {

        if (!Boolean.parseBoolean(isBasicAuthEnabled(tenantDomain))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Basic Authentication is not enabled for outbound analytics calls in for the tenant:" +
                        tenantDomain);
            }
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Basic Authentication enabled for outbound analytics calls in the tenant:" + tenantDomain);
        }
        String username = getUsername(tenantDomain);
        String password = getPassword(tenantDomain);

        AuthenticationManager authenticationManager = authenticationFactory.getAuthenticationManager("Basic");
        request.setHeader(authenticationManager.authenticate(new UsernamePasswordCredentials(username,
                password), request));
    }

    protected String getPassword(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl.CREDENTIAL, tenantDomain);
    }

    protected String getUsername(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl.USERNAME, tenantDomain);
    }

    protected String isBasicAuthEnabled(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl.BASIC_AUTH_ENABLED, tenantDomain);
    }
}

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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.CHOREO_DOMAINS;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.CHOREO_TOKEN_ENDPOINT;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_CONNECTION_REQUEST_TIMEOUT;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_CONNECTION_TIMEOUT;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_FUNCTION_ALLOWED_DOMAINS;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_READ_TIMEOUT;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_REQUEST_RETRY_COUNT;

public class ConfigProvider {

    private static final Log LOG = LogFactory.getLog(ConfigProvider.class);

    private int connectionTimeout;
    private int readTimeout;
    private int connectionRequestTimeout;
    private int requestRetryCount = 2;
    private List<String> httpFunctionAllowedDomainList = new ArrayList<>();
    private List<String> choreoDomainList = new ArrayList<>();
    private final String choreoTokenEndpoint;

    private static ConfigProvider instance = new ConfigProvider();

    private ConfigProvider() {

        int defaultTimeout = 5000;
        String connectionTimeoutString = IdentityUtil.getProperty(HTTP_CONNECTION_TIMEOUT);
        String readTimeoutString = IdentityUtil.getProperty(HTTP_READ_TIMEOUT);
        String connectionRequestTimeoutString = IdentityUtil.getProperty(HTTP_CONNECTION_REQUEST_TIMEOUT);
        String requestRetryCountString = IdentityUtil.getProperty(HTTP_REQUEST_RETRY_COUNT);
        List<String> httpFunctionAllowedDomainList = IdentityUtil.getPropertyAsList(HTTP_FUNCTION_ALLOWED_DOMAINS);
        List<String> choreoDomainList = IdentityUtil.getPropertyAsList(CHOREO_DOMAINS);

        this.choreoTokenEndpoint = IdentityUtil.getProperty(CHOREO_TOKEN_ENDPOINT);
        connectionTimeout = defaultTimeout;
        readTimeout = defaultTimeout;
        connectionRequestTimeout = defaultTimeout;

        if (connectionTimeoutString != null) {
            try {
                connectionTimeout = Integer.parseInt(connectionTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("Error while parsing connection timeout : " + connectionTimeoutString, e);
            }
        }
        if (readTimeoutString != null) {
            try {
                readTimeout = Integer.parseInt(readTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("Error while parsing read timeout : " + connectionTimeoutString, e);
            }
        }
        if (connectionRequestTimeoutString != null) {
            try {
                connectionRequestTimeout = Integer.parseInt(connectionRequestTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("Error while parsing connection request timeout : " + connectionTimeoutString, e);
            }
        }
        if (requestRetryCountString != null) {
            try {
                requestRetryCount = Integer.parseInt
                        (requestRetryCountString);
            } catch (NumberFormatException e) {
                LOG.error("Error while parsing max request attempts for api endpoint timeout : " +
                        requestRetryCountString, e);
            }
        }

        if (httpFunctionAllowedDomainList != null) {
            this.httpFunctionAllowedDomainList = httpFunctionAllowedDomainList;
        }
        if (this.httpFunctionAllowedDomainList.isEmpty() && LOG.isDebugEnabled()) {
            LOG.debug("Allowed domains for http functions are not configured therefore domain restriction is " +
                    "turned off for adaptive auth http functions.");

        }

        if (choreoDomainList != null) {
            this.choreoDomainList = choreoDomainList;
        }
        if (this.choreoDomainList.isEmpty() && LOG.isDebugEnabled()) {
            LOG.debug("Choreo domain list used by the callChore function is not configured therefore domain" +
                    " restriction is turned off for callChoreo function.");
        }
    }

    public static ConfigProvider getInstance() {

        return instance;
    }

    public int getConnectionTimeout() {

        return connectionTimeout;
    }

    public int getReadTimeout() {

        return readTimeout;
    }

    public int getConnectionRequestTimeout() {

        return connectionRequestTimeout;
    }

    public int getRequestRetryCount() {

        return requestRetryCount;
    }

    public List<String> getAllowedDomainsForHttpFunctions() {

        return httpFunctionAllowedDomainList;
    }

    public List<String> getChoreoDomains() {

        return choreoDomainList;
    }

    public String getChoreoTokenEndpoint() {

        return choreoTokenEndpoint;
    }
}

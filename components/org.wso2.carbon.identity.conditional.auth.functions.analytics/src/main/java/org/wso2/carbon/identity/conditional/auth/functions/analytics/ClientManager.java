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

package org.wso2.carbon.identity.conditional.auth.functions.analytics;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.wso2.carbon.identity.conditional.auth.functions.analytics.internal.AnalyticsFunctionsServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;

import javax.net.ssl.SSLContext;

/**
 * Class to retrieve the HTTP Clients.
 */
public class ClientManager {

    private static final Log LOG = LogFactory.getLog(ClientManager.class);

    private PoolingHttpClientConnectionManager poolingHttpClientConnectionManager;

    private static ClientManager instance = new ClientManager();

    public static ClientManager getInstance() {

        return instance;
    }

    private ClientManager() {

        String maxConnectionsString = IdentityUtil.getProperty(Constants.CONNECTION_POOL_MAX_CONNECTIONS);
        String maxConnectionsPerRouteString = IdentityUtil.getProperty(Constants
                .CONNECTION_POOL_MAX_CONNECTIONS_PER_ROUTE);
        int defaultMaxConnections = 20;
        int maxConnections = defaultMaxConnections;
        int maxConnectionsPerRoute = defaultMaxConnections;
        try {
            maxConnections = Integer.parseInt(maxConnectionsString);
        } catch (NumberFormatException e) {
            // Ignore. Default value is used.
        }
        try {
            maxConnectionsPerRoute = Integer.parseInt(maxConnectionsPerRouteString);
        } catch (NumberFormatException e) {
            // Ignore. Default value is used.
        }


        poolingHttpClientConnectionManager = new PoolingHttpClientConnectionManager();
        // Increase max total connection to 50
        poolingHttpClientConnectionManager.setMaxTotal(maxConnections);
        // Increase default max connection per route to 50
        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxConnectionsPerRoute);
    }

    /**
     * Get HTTPClient properly configured with tenant configurations.
     *
     * @param tenantDomain tenant domain of the service provider.
     * @return HttpClient
     */
    public CloseableHttpClient getClient(String tenantDomain) {

        CloseableHttpClient client;

        int defaultTimeout = 5000;
        String connectionTimeoutString = null;
        String readTimeoutString = null;
        String connectionRequestTimeoutString = null;
        try {
            connectionTimeoutString = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HTTP_CONNECTION_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }
        try {
            readTimeoutString = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HTTP_READ_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }
        try {
            connectionRequestTimeoutString = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HTTP_CONNECTION_REQUEST_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }

        int connectionTimeout = defaultTimeout;
        int readTimeout = defaultTimeout;
        int connectionRequestTimeout = defaultTimeout;

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

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(connectionTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout)
                .setSocketTimeout(readTimeout)
                .build();
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create().setDefaultRequestConfig(config);

        addSslContext(httpClientBuilder, tenantDomain);
        addConnectionManager(httpClientBuilder);

        client = httpClientBuilder.build();

        return client;
    }

    private void addSslContext(HttpClientBuilder builder, String tenantDomain) {

        try {
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(AnalyticsFunctionsServiceHolder.getInstance().getTrustStore())
                    .build();

            String hostnameVerifierConfig = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HOSTNAME_VERIFIER, tenantDomain);
            X509HostnameVerifier hostnameVerifier;
            if (AnalyticsEngineConfigImpl.HOSTNAME_VERIFIER_STRICT.equalsIgnoreCase(hostnameVerifierConfig)) {
                hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
            } else if (AnalyticsEngineConfigImpl.HOSTNAME_VERIFIER_ALLOW_ALL.equalsIgnoreCase(hostnameVerifierConfig)) {
                hostnameVerifier = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            } else {
                hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
            }
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                    sslContext,
                    null,
                    null,
                    hostnameVerifier);

            builder.setSSLSocketFactory(sslSocketFactory);
        } catch (Exception e) {
            LOG.error("Error while creating ssl context for analytics endpoint invocation in tenant domain: " +
                    tenantDomain, e);
        }
    }

    private void addConnectionManager(HttpClientBuilder builder) {

        builder.setConnectionManager(poolingHttpClientConnectionManager);
    }
}

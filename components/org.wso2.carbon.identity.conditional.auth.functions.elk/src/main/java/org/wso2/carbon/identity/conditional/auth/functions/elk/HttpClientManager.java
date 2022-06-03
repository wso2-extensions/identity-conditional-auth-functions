/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.elk;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.nio.reactor.ConnectingIOReactor;
import org.apache.http.nio.reactor.IOReactorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.conditional.auth.functions.elk.internal.ElasticFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Class to retrieve the HTTP Clients.
 */
public class HttpClientManager {

    private static final Log LOG = LogFactory.getLog(HttpClientManager.class);

    private static HttpClientManager instance = new HttpClientManager();

    private static Map<Integer, CloseableHttpAsyncClient> clientMap = new HashMap<>();

    public static HttpClientManager getInstance() {

        return instance;
    }

    private HttpClientManager() {

    }

    /**
     * Get HTTPClient properly configured with tenant configurations.
     *
     * @param tenantDomain tenant domain of the service provider.
     * @return HttpClient
     */
    public CloseableHttpAsyncClient getClient(String tenantDomain) throws FrameworkException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        CloseableHttpAsyncClient client = clientMap.get(tenantId);

        if (client == null) {

            PoolingNHttpClientConnectionManager poolingHttpClientConnectionManager = createPoolingConnectionManager();

            RequestConfig config = createRequestConfig(tenantDomain);

            HttpAsyncClientBuilder httpClientBuilder = HttpAsyncClients.custom().setDefaultRequestConfig(config);

            addSslContext(httpClientBuilder, tenantDomain);
            httpClientBuilder.setConnectionManager(poolingHttpClientConnectionManager);

            client = httpClientBuilder.build();
            client.start();
            clientMap.put(tenantId, client);
        }

        return client;
    }

    private RequestConfig createRequestConfig(String tenantDomain) {

        int defaultTimeout = 5000;
        String connectionTimeoutString = null;
        String readTimeoutString = null;
        String connectionRequestTimeoutString = null;
        try {
            connectionTimeoutString = CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl
                    .HTTP_CONNECTION_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }
        try {
            readTimeoutString = CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl
                    .HTTP_READ_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }
        try {
            connectionRequestTimeoutString = CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl
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

        return RequestConfig.custom()
                .setConnectTimeout(connectionTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout)
                .setSocketTimeout(readTimeout)
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
    }

    private PoolingNHttpClientConnectionManager createPoolingConnectionManager() throws FrameworkException {

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

        ConnectingIOReactor ioReactor;
        try {
            ioReactor = new DefaultConnectingIOReactor();
        } catch (IOReactorException e) {
            throw new FrameworkException("Error while creating ConnectingIOReactor", e);
        }
        PoolingNHttpClientConnectionManager poolingHttpClientConnectionManager = new
                PoolingNHttpClientConnectionManager(ioReactor);
        // Increase max total connection to 50
        poolingHttpClientConnectionManager.setMaxTotal(maxConnections);
        // Increase default max connection per route to 50
        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxConnectionsPerRoute);
        return poolingHttpClientConnectionManager;
    }

    public void closeClient(int tenantId) throws IOException {

        CloseableHttpAsyncClient client = clientMap.get(tenantId);

        if (client != null) {
            clientMap.remove(tenantId);
            client.close();
        }
    }

    private void addSslContext(HttpAsyncClientBuilder builder, String tenantDomain) {

        try {
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(ElasticFunctionsServiceHolder.getInstance().getTrustStore())
                    .build();

            String hostnameVerifierConfig = CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl
                    .HOSTNAME_VERIFIER, tenantDomain);
            X509HostnameVerifier hostnameVerifier;
            if (ElasticAnalyticsEngineConfigImpl.HOSTNAME_VERIFIER_STRICT.equalsIgnoreCase(hostnameVerifierConfig)) {
                hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
            } else if (ElasticAnalyticsEngineConfigImpl.HOSTNAME_VERIFIER_ALLOW_ALL.equalsIgnoreCase(hostnameVerifierConfig)) {
                hostnameVerifier = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            } else {
                hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
            }

            builder.setSSLContext(sslContext);
            builder.setHostnameVerifier(hostnameVerifier);
        } catch (Exception e) {
            LOG.error("Error while creating ssl context for analytics endpoint invocation in tenant domain: " +
                    tenantDomain, e);
        }
    }

}

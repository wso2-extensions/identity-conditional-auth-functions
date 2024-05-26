/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.elk;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.util.EntityUtils;
import org.graalvm.polyglot.HostAccess;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.conditional.auth.functions.elk.util.ElasticConfigProvider;
import org.wso2.carbon.identity.event.IdentityEventException;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ContentTypes.TYPE_APPLICATION_JSON;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.*;

/**
 * Implementation of the {@link CallElasticFunction}.
 */
public class CallElasticFunctionImpl extends AbstractElasticHelper implements CallElasticFunction {

    private static final Log LOG = LogFactory.getLog(CallElasticFunctionImpl.class);

    private static final ElasticConfigProvider elasticConfigProvider = ElasticConfigProvider.getInstance();

    public CallElasticFunctionImpl() {

        super();
    }

    @Override
    @HostAccess.Export
    public void callElastic(Map<String, String> params, Map<String, Object> eventHandlers) {

        Map<String, String> paramsMap = new HashMap<>(params);
        AsyncProcess asyncProcess = new AsyncProcess((authenticationContext, asyncReturn) -> {

            try {
                String tenantDomain = authenticationContext.getTenantDomain();
                String targetHostUrl = CommonUtils.getConnectorConfig(ElasticAnalyticsEngineConfigImpl.RECEIVER,
                        tenantDomain);
                if (targetHostUrl == null) {
                    throw new FrameworkException("Elasticsearch host cannot be found.");
                }

                HttpPost request = new HttpPost(elasticConfigProvider.getElasticSearchUrl(targetHostUrl,paramsMap));

                request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
                request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
                handleAuthentication(request, authenticationContext.getTenantDomain());

                String query = elasticConfigProvider.getQuery(paramsMap);
                request.setEntity(new StringEntity(query, StandardCharsets.UTF_8));

                String[] targetHostUrls = targetHostUrl.split(";");

                HttpHost[] targetHosts = new HttpHost[targetHostUrls.length];

                for (int i = 0; i < targetHostUrls.length; i++) {
                    URL hostUrl = new URL(targetHostUrls[i]);
                    targetHosts[i] = new HttpHost(hostUrl.getHost(), hostUrl.getPort(), hostUrl.getProtocol());
                }

                CloseableHttpAsyncClient client = HttpClientManager.getInstance().getClient(tenantDomain);

                AtomicInteger requestAtomicInteger = new AtomicInteger(targetHosts.length);

                for (final HttpHost targetHost : targetHosts) {
                    client.execute(targetHost, request, new FutureCallback<HttpResponse>() {

                        @Override
                        public void completed(final HttpResponse response) {

                            int responseCode = response.getStatusLine().getStatusCode();
                            try {
                                Map<String, Object> responseMap = new HashMap<>();
                                if (responseCode == 200) {
                                    try {
                                        String jsonString = EntityUtils.toString(response.getEntity());
                                        JSONObject responseBody = new JSONObject(jsonString);
                                        int score = responseBody
                                                .getJSONObject("aggregations")
                                                .getJSONObject("risk_score")
                                                .getInt("value");
                                        responseMap.put("risk_score", score);
                                        asyncReturn.accept(authenticationContext, responseMap, OUTCOME_SUCCESS);
                                    } catch (JSONException e) {
                                        LOG.error("Error while building response from analytics engine call for " +
                                                "session data key: " + authenticationContext.getContextIdentifier(), e);
                                        asyncReturn.accept(authenticationContext, responseMap, OUTCOME_FAIL);
                                    } catch (IOException e) {
                                        LOG.error("Error while reading response from analytics engine call for " +
                                                "session data key: " + authenticationContext.getContextIdentifier(), e);
                                        asyncReturn.accept(authenticationContext, responseMap, OUTCOME_FAIL);
                                    }
                                } else {
                                    asyncReturn.accept(authenticationContext, responseMap, OUTCOME_FAIL);
                                }
                            } catch (FrameworkException e) {
                                LOG.error("Error while proceeding after successful response from analytics engine " +
                                                "call for session data key: " + authenticationContext.getContextIdentifier(),
                                        e);
                            }
                        }

                        @Override
                        public void failed(final Exception ex) {

                            LOG.error("Failed to invoke analytics engine for session data key: " +
                                    authenticationContext.getContextIdentifier(), ex);
                            if (requestAtomicInteger.decrementAndGet() <= 0) {
                                try {
                                    if (LOG.isDebugEnabled()) {
                                        LOG.debug(" All the calls to analytics engine failed for session " +
                                                "data key: " + authenticationContext.getContextIdentifier());
                                    }
                                    String outcome = OUTCOME_FAIL;
                                    if ((ex instanceof SocketTimeoutException)
                                            || (ex instanceof ConnectTimeoutException)) {
                                        outcome = OUTCOME_TIMEOUT;
                                    }
                                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), outcome);
                                } catch (FrameworkException e) {
                                    LOG.error("Error while proceeding after failed response from analytics engine " +
                                            "call for session data key: " + authenticationContext
                                            .getContextIdentifier(), e);
                                }
                            }
                        }

                        @Override
                        public void cancelled() {

                            LOG.error("Invocation analytics engine for session data key: " +
                                    authenticationContext.getContextIdentifier() + " is cancelled.");
                            if (requestAtomicInteger.decrementAndGet() <= 0) {
                                try {
                                    if (LOG.isDebugEnabled()) {
                                        LOG.debug(" All the calls to analytics engine failed for session " +
                                                "data key: " + authenticationContext.getContextIdentifier());
                                    }
                                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                                } catch (FrameworkException e) {
                                    LOG.error("Error while proceeding after cancelled response from analytics engine " +
                                            "call for session data key: " + authenticationContext
                                            .getContextIdentifier(), e);
                                }
                            }
                        }

                    });
                }

            } catch (IdentityEventException e) {
                LOG.error("Error while creating authentication. ", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (IOException e) {
                LOG.error("Reading query config file failed.");
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            }

        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }
}

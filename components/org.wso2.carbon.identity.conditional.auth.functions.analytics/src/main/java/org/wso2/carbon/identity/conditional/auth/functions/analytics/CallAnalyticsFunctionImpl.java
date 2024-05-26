/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.analytics;

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
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.event.IdentityEventException;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_SUCCESS;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_TIMEOUT;

/**
 * Implementation of the {@link CallAnalyticsFunction}
 */
public class CallAnalyticsFunctionImpl extends AbstractAnalyticsFunction implements CallAnalyticsFunction {

    private static final Log LOG = LogFactory.getLog(CallAnalyticsFunctionImpl.class);
    private static final String PARAM_APP_NAME = "Application";
    private static final String PARAM_INPUT_STREAM = "InputStream";

    @Override
    @HostAccess.Export
    public void callAnalytics(Map<String, String> metadata,
                              Map<String, Object> payloadData, Map<String, Object> eventHandlers) {

        /*
         * Here, we need to clone the parameters since, even though we're accessing the parameters as Map objects,
         * these may be instances of child classes of Map class (Script Engine specific implementations).
         * When the AsyncProcess is executed, the objects will not be available if the relevant Script Engine is closed.
         * Eg: Polyglot Map (Map implementation from GraalJS) will be unavailable when the Polyglot Context is closed.
         */
        Map<String, String> metadataMap = new HashMap<>(metadata);
        Map<String, Object> payloadDataMap = new HashMap<>(payloadData);
        AsyncProcess asyncProcess = new AsyncProcess((authenticationContext, asyncReturn) -> {

            String appName = metadataMap.get(PARAM_APP_NAME);
            String inputStream = metadataMap.get(PARAM_INPUT_STREAM);
            String receiverUrl = metadataMap.get(PARAM_EP_URL);
            String targetPath;
            try {
                if (appName != null && inputStream != null) {
                    targetPath = "/" + appName + "/" + inputStream;
                } else if (receiverUrl != null) {
                    targetPath = receiverUrl;
                } else {
                    throw new FrameworkException("Target path cannot be found.");
                }
                String tenantDomain = authenticationContext.getTenantDomain();
                String targetHostUrl = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl.RECEIVER,
                        tenantDomain);

                if (targetHostUrl == null) {
                    throw new FrameworkException("Target host cannot be found.");
                }

                HttpPost request = new HttpPost(targetPath);
                request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
                request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
                handleAuthentication(request, tenantDomain);

                JSONObject jsonObject = new JSONObject();
                JSONObject event = new JSONObject();
                for (Map.Entry<String, Object> dataElements : payloadDataMap.entrySet()) {
                    event.put(dataElements.getKey(), dataElements.getValue());
                }
                jsonObject.put("event", event);
                request.setEntity(new StringEntity(jsonObject.toJSONString()));

                String[] targetHostUrls = targetHostUrl.split(";");

                HttpHost[] targetHosts = new HttpHost[targetHostUrls.length];

                for (int i = 0; i < targetHostUrls.length; i++) {
                    URL hostUrl = new URL(targetHostUrls[i]);
                    targetHosts[i] = new HttpHost(hostUrl.getHost(), hostUrl.getPort(), hostUrl.getProtocol());
                }

                CloseableHttpAsyncClient client = ClientManager.getInstance().getClient(tenantDomain);

                AtomicInteger requestAtomicInteger = new AtomicInteger(targetHosts.length);

                for (final HttpHost targetHost : targetHosts) {
                    client.execute(targetHost, request, new FutureCallback<HttpResponse>() {

                        @Override
                        public void completed(final HttpResponse response) {

                            int responseCode = response.getStatusLine().getStatusCode();
                            try {
                                if (responseCode == 200) {
                                    try {
                                        String jsonString = EntityUtils.toString(response.getEntity());
                                        JSONParser parser = new JSONParser();
                                        JSONObject json = (JSONObject) parser.parse(jsonString);
                                        asyncReturn.accept(authenticationContext, json, OUTCOME_SUCCESS);
                                    } catch (ParseException e) {
                                        LOG.error("Error while building response from analytics engine call for " +
                                                "session data key: " + authenticationContext.getContextIdentifier(), e);
                                        asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                                    } catch (IOException e) {
                                        LOG.error("Error while reading response from analytics engine call for " +
                                                "session data key: " + authenticationContext.getContextIdentifier(), e);
                                        asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                                    }
                                } else {
                                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
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

            } catch (IOException e) {
                LOG.error("Error while calling analytics engine. ", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (IdentityEventException e) {
                LOG.error("Error while creating authentication. ", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            }
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }
}

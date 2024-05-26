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
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.graalvm.polyglot.HostAccess;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.event.IdentityEventException;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.apache.http.HttpHeaders.CONTENT_TYPE;

/**
 * Implementation of the {@link PublishToAnalyticsFunction}
 */
public class PublishToAnalyticsFunctionImpl extends AbstractAnalyticsFunction implements PublishToAnalyticsFunction {

    private static final Log LOG = LogFactory.getLog(PublishToAnalyticsFunctionImpl.class);
    private static final String PARAM_APP_NAME = "Application";
    private static final String PARAM_INPUT_STREAM = "InputStream";

    @Override
    @HostAccess.Export
    public void publishToAnalytics(Map<String, String> metadata, Map<String, Object> payloadData,
                                   JsAuthenticationContext context) {

        /*
         * Here, we need to clone the parameters since, even though we're accessing the parameters as Map objects,
         * these may be instances of child classes of Map class (Script Engine specific implementations).
         * When the AsyncProcess is executed, the objects will not be available if the relevant Script Engine is closed.
         * Eg: Polyglot Map (Map implementation from GraalJS) will be unavailable when the Polyglot Context is closed.
         */
        Map<String, String> metadataMap = new HashMap<>(metadata);
        Map<String, Object> payloadDataMap = new HashMap<>(payloadData);
        String contextIdentifier = context.getWrapped().getContextIdentifier();

        String appName = metadataMap.get(PARAM_APP_NAME);
        String inputStream = metadataMap.get(PARAM_INPUT_STREAM);
        String targetPath = metadataMap.get(PARAM_EP_URL);
        String epUrl = null;
        try {
            if (appName != null && inputStream != null) {
                epUrl = "/" + appName + "/" + inputStream;
            } else if (targetPath != null) {
                epUrl = targetPath;
            } else {
                LOG.error("Target path cannot be found.");
                return;
            }
            String tenantDomain = context.getWrapped().getTenantDomain();
            String targetHostUrl = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl.RECEIVER, tenantDomain);
            if (targetHostUrl == null) {
                LOG.error("Target host cannot be found.");
                return;
            }

            HttpPost request = new HttpPost(epUrl);
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

            for (final HttpHost targetHost : targetHosts) {
                client.execute(targetHost, request, new FutureCallback<HttpResponse>() {

                    @Override
                    public void completed(final HttpResponse response) {

                        int responseCode = response.getStatusLine().getStatusCode();
                        if (responseCode == 200) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Successfully published data to the analytics for session data key: " +
                                        contextIdentifier);
                            }
                        } else {
                            LOG.error("Error while publishing data to analytics engine for session data key: " +
                                    contextIdentifier + ". Request completed successfully. " +
                                    "But response code was not 200");
                        }
                    }

                    @Override
                    public void failed(final Exception ex) {

                        LOG.error("Error while publishing data to analytics engine for session data key: " +
                                contextIdentifier + ". Request failed with: " + ex);
                    }

                    @Override
                    public void cancelled() {

                        LOG.error("Error while publishing data to analytics engine for session data key: " +
                                contextIdentifier + ". Request canceled.");
                    }
                });
            }

        } catch (IOException e) {
            LOG.error("Error while calling analytics engine for tenant: " + context.getWrapped().getTenantDomain(), e);
        } catch (IdentityEventException e) {
            LOG.error("Error while preparing authentication information for tenant: " + context.getWrapped()
                    .getTenantDomain(), e);
        } catch (FrameworkException e) {
            LOG.error("Error while building client to invoke analytics engine for tenant: " + context.getWrapped()
                    .getTenantDomain(), e);
        }
    }
}

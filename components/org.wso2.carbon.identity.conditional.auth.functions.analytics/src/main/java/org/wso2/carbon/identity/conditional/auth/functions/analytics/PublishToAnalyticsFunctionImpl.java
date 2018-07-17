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
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.event.IdentityEventException;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
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
    public void publishToAnalytics(Map<String, String> metadata, Map<String, Object> payloadData,
                                   JsAuthenticationContext context) {

        String appName = metadata.get(PARAM_APP_NAME);
        String inputStream = metadata.get(PARAM_INPUT_STREAM);
        String targetPath = metadata.get(PARAM_EP_URL);
        String epUrl = null;
        try {
            if (appName != null && inputStream != null) {
                epUrl = appName + "/" + inputStream;
            } else if (targetPath != null) {
                epUrl = targetPath;
            } else {
                LOG.error("Target path cannot be found.");
                return;
            }
            String tenantDomain = context.getContext().getTenantDomain();
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
            for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                event.put(dataElements.getKey(), dataElements.getValue());
            }
            jsonObject.put("event", event);
            request.setEntity(new StringEntity(jsonObject.toJSONString()));

            URL hostUrl = new URL(targetHostUrl);
            HttpHost targetHost = new HttpHost(hostUrl.getHost(), hostUrl.getPort());

            CloseableHttpClient client = ClientManager.getInstance().getClient(tenantDomain);
            try (CloseableHttpResponse response = client.execute(targetHost, request)) {
                EntityUtils.consume(response.getEntity());
            }

        }  catch (ConnectTimeoutException e) {
            LOG.error("Error while waiting to connect to " + epUrl, e);
        } catch (SocketTimeoutException e) {
            LOG.error("Error while waiting for data from " + epUrl, e);
        } catch (IOException e) {
            LOG.error("Error while calling siddhi.", e);
        } catch (IdentityEventException e) {
            LOG.error("Error while creating authentication.", e);
        }
    }
}

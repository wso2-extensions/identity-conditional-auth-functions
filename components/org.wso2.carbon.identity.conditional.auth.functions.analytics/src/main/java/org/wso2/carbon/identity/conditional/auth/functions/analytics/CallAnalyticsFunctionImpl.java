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
import java.util.Map;

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
    public void callAnalytics(Map<String, String> metadata,
                              Map<String, Object> payloadData, Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((authenticationContext, asyncReturn) -> {
            JSONObject json = null;
            int responseCode;
            String outcome;
            String appName = metadata.get(PARAM_APP_NAME);
            String inputStream = metadata.get(PARAM_INPUT_STREAM);
            String receiverUrl = metadata.get(PARAM_EP_URL);
            String targetPath = null;
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
                for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                    event.put(dataElements.getKey(), dataElements.getValue());
                }
                jsonObject.put("event", event);
                request.setEntity(new StringEntity(jsonObject.toJSONString()));

                URL hostUrl = new URL(targetHostUrl);
                HttpHost targetHost = new HttpHost(hostUrl.getHost(), hostUrl.getPort(), hostUrl.getProtocol());

                CloseableHttpClient client = ClientManager.getInstance().getClient(tenantDomain);
                try (CloseableHttpResponse response = client.execute(targetHost, request)) {
                    responseCode = response.getStatusLine().getStatusCode();

                    if (responseCode == 200) {
                        outcome = OUTCOME_SUCCESS;
                        String jsonString = EntityUtils.toString(response.getEntity());
                        JSONParser parser = new JSONParser();
                        json = (JSONObject) parser.parse(jsonString);
                    } else {
                        outcome = OUTCOME_FAIL;
                    }
                }

            } catch (FrameworkException e) {
                LOG.error("Error while generating request. ", e);
                outcome = OUTCOME_FAIL;
            } catch (ConnectTimeoutException e) {
                LOG.error("Error while waiting to connect to " + targetPath, e);
                outcome = OUTCOME_TIMEOUT;
            } catch (SocketTimeoutException e) {
                LOG.error("Error while waiting for data from " + targetPath, e);
                outcome = OUTCOME_TIMEOUT;
            } catch (IOException e) {
                LOG.error("Error while calling analytics engine. ", e);
                outcome = OUTCOME_FAIL;
            } catch (ParseException e) {
                LOG.error("Error while parsing response. ", e);
                outcome = OUTCOME_FAIL;
            } catch (IdentityEventException e) {
                LOG.error("Error while creating authentication. ", e);
                outcome = OUTCOME_FAIL;
            }

            asyncReturn.accept(authenticationContext, json != null ? json : Collections.emptyMap(), outcome);
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }
}

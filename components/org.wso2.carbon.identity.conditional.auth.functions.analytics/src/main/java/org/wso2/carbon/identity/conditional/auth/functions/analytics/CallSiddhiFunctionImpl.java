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
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.conditional.auth.functions.analytics.utils.AnalyticsConstants;
import org.wso2.carbon.identity.conditional.auth.functions.analytics.utils.ConfigProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.Map;
import java.util.function.Consumer;

import static javax.ws.rs.core.HttpHeaders.ACCEPT;
import static javax.ws.rs.core.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.analytics.utils.AnalyticsConstants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.conditional.auth.functions.analytics.utils.AnalyticsConstants.OUTCOME_SUCCESS;
import static org.wso2.carbon.identity.conditional.auth.functions.analytics.utils.AnalyticsConstants.OUTCOME_TIMEOUT;

/**
 * Implementation of the {@link CallSiddhiFunction}
 */
public class CallSiddhiFunctionImpl implements CallSiddhiFunction {

    private static final Log LOG = LogFactory.getLog(CallSiddhiFunctionImpl.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";


    private CloseableHttpClient client;
    private String receiverEp;

    public CallSiddhiFunctionImpl() {

        this.receiverEp = IdentityUtil.getProperty(AnalyticsConstants.RECEIVER_URL);

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(ConfigProvider.getInstance().getConnectionTimeout())
                .setConnectionRequestTimeout(ConfigProvider.getInstance().getConnectionRequestTimeout())
                .setSocketTimeout(ConfigProvider.getInstance().getReadTimeout())
                .build();
        client = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
    }

    @Override
    public void callSiddhi(String siddhiAppName, String inStreamName, String outStreamName,
                              Map<String, Object> payloadData, Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((context, asyncReturn) -> {
            JSONObject json = null;
            int responseCode;
            String outcome;

            String epUrl = receiverEp + siddhiAppName + "/" + inStreamName;
            HttpPost request = new HttpPost(epUrl);
            try {
                request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
                request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);

                JSONObject jsonObject = new JSONObject();
                JSONObject event = new JSONObject();
                for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                    event.put(dataElements.getKey(), dataElements.getValue());
                }
                jsonObject.put("event", event);
                request.setEntity(new StringEntity(jsonObject.toJSONString()));

                HttpResponse response = client.execute(request);
                responseCode = response.getStatusLine().getStatusCode();

                if (responseCode == 200) {
                    outcome = OUTCOME_SUCCESS;
                    String jsonString = EntityUtils.toString(response.getEntity());
                    JSONParser parser = new JSONParser();
                    json = (JSONObject) parser.parse(jsonString);
                } else {
                    outcome = OUTCOME_FAIL;
                }

            }  catch (ConnectTimeoutException e) {
                LOG.error("Error while waiting to connect to " + epUrl, e);
                outcome = OUTCOME_TIMEOUT;
            } catch (SocketTimeoutException e) {
                LOG.error("Error while waiting for data from " + epUrl, e);
                outcome = OUTCOME_TIMEOUT;
            } catch (IOException e) {
                LOG.error("Error while calling siddhi. ", e);
                outcome = OUTCOME_FAIL;
            } catch (ParseException e) {
                LOG.error("Error while parsing response. ", e);
                outcome = OUTCOME_FAIL;
            }

            asyncReturn.accept(context, json != null ? json : Collections.emptyMap(), outcome);
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }
}

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
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.conditional.auth.functions.analytics.utils.AnalyticsConstants;
import org.wso2.carbon.identity.conditional.auth.functions.analytics.utils.ConfigProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Map;

import static javax.ws.rs.core.HttpHeaders.CONTENT_TYPE;

/**
 * Implementation of the {@link PublishToAnalyticsFunction}
 */
public class PublishToAnalyticsFunctionImpl implements PublishToAnalyticsFunction {

    private static final Log LOG = LogFactory.getLog(PublishToAnalyticsFunctionImpl.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";
    private static final String PARAM_APP_NAME = "Application";
    private static final String PARAM_INPUT_STREAM = "InputStream";
    private static final String PARAM_EP_URL = "ReceiverUrl";

    private CloseableHttpClient client;
    private String receiverEp;

    public PublishToAnalyticsFunctionImpl() {

        this.receiverEp = IdentityUtil.getProperty(AnalyticsConstants.RECEIVER_URL);

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(ConfigProvider.getInstance().getConnectionTimeout())
                .setConnectionRequestTimeout(ConfigProvider.getInstance().getConnectionRequestTimeout())
                .setSocketTimeout(ConfigProvider.getInstance().getReadTimeout())
                .build();
        client = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
    }

    @Override
    public void publishToAnalytics(Map<String, String> metadata, Map<String, Object> payloadData) {

        String appName = metadata.get(PARAM_APP_NAME);
        String inputStream = metadata.get(PARAM_INPUT_STREAM);
        String receiverUrl = metadata.get(PARAM_EP_URL);
        String epUrl;
        if (appName != null && inputStream != null) {
            epUrl = receiverEp + appName + "/" + inputStream;
        } else if (receiverUrl != null) {
            epUrl = receiverUrl;
        } else {
            LOG.error("Receiver url cannot be found.");
            return;
        }

        HttpPost request = new HttpPost(epUrl);
        try {
            request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);

            JSONObject jsonObject = new JSONObject();
            JSONObject event = new JSONObject();
            for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                event.put(dataElements.getKey(), dataElements.getValue());
            }
            jsonObject.put("event", event);
            request.setEntity(new StringEntity(jsonObject.toJSONString()));

            try (CloseableHttpResponse response = client.execute(request)) {
                EntityUtils.consume(response.getEntity());
            }

        }  catch (ConnectTimeoutException e) {
            LOG.error("Error while waiting to connect to " + epUrl, e);
        } catch (SocketTimeoutException e) {
            LOG.error("Error while waiting for data from " + epUrl, e);
        } catch (IOException e) {
            LOG.error("Error while calling siddhi. ", e);
        }
    }
}

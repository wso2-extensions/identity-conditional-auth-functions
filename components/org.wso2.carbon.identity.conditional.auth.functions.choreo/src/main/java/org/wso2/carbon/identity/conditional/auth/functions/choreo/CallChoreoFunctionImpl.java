/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.choreo;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.internal.ChoreoFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.secret.mgt.core.exception.SecretManagementException;
import org.wso2.carbon.identity.secret.mgt.core.model.ResolvedSecret;


import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_TIMEOUT;

/**
 * Implementation of the {@link CallChoreoFunction}
 */
public class CallChoreoFunctionImpl implements CallChoreoFunction {

    private static final Log LOG = LogFactory.getLog(CallChoreoFunction.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";
    private static final String API_KEY = "API-Key";

    private static final String URL_VARIABLE_NAME = "url";
    private static final String API_KEY_VARIABLE_NAME = "apiKey";
    private static final String API_KEY_ALIAS_VARIABLE_NAME = "apiKeyAlias";
    private static final String SECRET_TYPE = "ADAPTIVE_AUTH_CALL_CHOREO";

    @Override
    public void callChoreo(Map<String, String> connectionMetaData, Map<String, Object> payloadData,
                           Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((authenticationContext, asyncReturn) -> {

            try {
                String epUrl = connectionMetaData.get(URL_VARIABLE_NAME);
                String tenantDomain = authenticationContext.getTenantDomain();

                HttpPost request = new HttpPost(epUrl);
                request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
                request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);

                String apiKey;
                if (StringUtils.isNotEmpty(connectionMetaData.get(API_KEY_VARIABLE_NAME))) {
                    apiKey = connectionMetaData.get(API_KEY_VARIABLE_NAME);
                } else {
                    String apiKeyAlias = connectionMetaData.get(API_KEY_ALIAS_VARIABLE_NAME);
                    apiKey = getResolvedSecret(apiKeyAlias);
                }
                request.setHeader(API_KEY, apiKey);

                JSONObject jsonObject = new JSONObject();
                for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                    jsonObject.put(dataElements.getKey(), dataElements.getValue());
                }
                request.setEntity(new StringEntity(jsonObject.toJSONString()));

                CloseableHttpAsyncClient client = ChoreoFunctionServiceHolder.getInstance().getClientManager()
                        .getClient(tenantDomain);
                client.execute(request, new FutureCallback<HttpResponse>() {

                    @Override
                    public void completed(final HttpResponse response) {

                        String outcome;
                        JSONObject json = null;
                        int responseCode = response.getStatusLine().getStatusCode();
                        try {
                            if (responseCode == 200) {
                                try {
                                    String jsonString = EntityUtils.toString(response.getEntity());
                                    JSONParser parser = new JSONParser();
                                    json = (JSONObject) parser.parse(jsonString);
                                    outcome = Constants.OUTCOME_SUCCESS;
                                } catch (ParseException e) {
                                    LOG.error("Error while building response from Choreo call for " +
                                            "session data key: " + authenticationContext.getContextIdentifier(), e);
                                    outcome = Constants.OUTCOME_FAIL;
                                } catch (IOException e) {
                                    LOG.error("Error while reading response from Choreo call for " +
                                            "session data key: " + authenticationContext.getContextIdentifier(), e);
                                    outcome = Constants.OUTCOME_FAIL;
                                }
                            } else {
                                outcome = Constants.OUTCOME_FAIL;
                            }
                            asyncReturn.accept(authenticationContext, json != null ? json : Collections.emptyMap(),
                                    outcome);
                        } catch (FrameworkException e) {
                            LOG.error("Error while proceeding after successful response from Choreo call for "
                                    + "session data key: " + authenticationContext.getContextIdentifier(), e);
                        }
                    }

                    @Override
                    public void failed(final Exception ex) {

                        LOG.error("Failed to invoke Choreo for session data key: " +
                                authenticationContext.getContextIdentifier(), ex);
                        try {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug(" Calls to Choreo failed for session " +
                                        "data key: " + authenticationContext.getContextIdentifier());
                            }
                            String outcome = OUTCOME_FAIL;
                            if ((ex instanceof SocketTimeoutException)
                                    || (ex instanceof ConnectTimeoutException)) {
                                outcome = OUTCOME_TIMEOUT;
                            }
                            asyncReturn.accept(authenticationContext, Collections.emptyMap(), outcome);
                        } catch (FrameworkException e) {
                            LOG.error("Error while proceeding after failed response from Choreo " +
                                    "call for session data key: " + authenticationContext
                                    .getContextIdentifier(), e);
                        }
                    }

                    @Override
                    public void cancelled() {

                        LOG.error("Invocation Choreo for session data key: " +
                                authenticationContext.getContextIdentifier() + " is cancelled.");
                        try {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug(" Calls to Choreo for session data key: "
                                        + authenticationContext.getContextIdentifier());
                            }
                            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                        } catch (FrameworkException e) {
                            LOG.error("Error while proceeding after cancelled response from Choreo " +
                                    "call for session data key: " + authenticationContext
                                    .getContextIdentifier(), e);
                        }
                    }
                });
            } catch (IllegalArgumentException e) {
                LOG.error("Invalid endpoint Url: ", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (IOException e) {
                LOG.error("Error while calling endpoint. ", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (SecretManagementException e) {
                LOG.error("Error while resolving API key. ", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            }
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }

    public String getResolvedSecret(String name) throws SecretManagementException {

        ResolvedSecret responseDTO = ChoreoFunctionServiceHolder.getInstance().
                getSecretConfigManager().getResolvedSecret(SECRET_TYPE, name);
        return responseDTO.getResolvedSecretValue();
    }
}

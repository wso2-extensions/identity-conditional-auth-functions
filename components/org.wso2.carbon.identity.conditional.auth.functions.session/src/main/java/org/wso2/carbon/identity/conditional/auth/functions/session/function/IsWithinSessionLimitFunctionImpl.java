/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.identity.conditional.auth.functions.session.function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.conditional.auth.functions.session.util.SessionValidationConstants;
import org.wso2.carbon.identity.conditional.auth.functions.session.util.SessionValidationUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static java.lang.Integer.parseInt;

/**
 * Represents javascript function provided in conditional authentication to check if the given user has valid number of
 * sessions.
 * The purpose is to perform dynamic authentication selection based on the active session count.
 *
 * @deprecated
 */
@Deprecated
public class IsWithinSessionLimitFunctionImpl implements IsWithinSessionLimitFunction {

    private static final Log log = LogFactory.getLog(IsWithinSessionLimitFunctionImpl.class);

    /**
     * Method to validate user session a given the authentication context and set of required attributes.
     *
     * @param context Authentication context
     * @param map     Hash map of attributes required for validation
     * @return boolean value indicating the validation success/failure
     * @throws FrameworkException when exception occurred in session retrieving method
     */
    @Override
    public boolean validate(JsAuthenticationContext context, Map<String, String> map)
            throws FrameworkException {

        boolean state = false;
        int sessionLimit = getSessionLimitFromMap(map);
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();

        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to find the authenticated user from the Authentication context.");
            }
            throw new FrameworkException("Unable to find the Authenticated user from previous step");
        }
        int sessionCount = getActiveSessionCount(authenticatedUser);
        if (log.isDebugEnabled()) {
            log.debug("Active session count: " + sessionCount + " and session limit : " + sessionLimit);
        }
        if (sessionCount < sessionLimit) {
            state = true;
        }
        return state;
    }

    /**
     * Method for retrieving user defined maximum session limit from parameter map.
     *
     * @param map parameter map passed from JS
     * @return inter indicating the maximum session Limit
     */
    private int getSessionLimitFromMap(Map<String, String> map) {

        return parseInt(map.get(SessionValidationConstants.SESSION_LIMIT_TAG));
    }

    /**
     * Method to retrieve active session count for the given authenticated user.
     *
     * @param authenticatedUser Authenticated user object
     * @return current active session count
     * @throws FrameworkException When the REST response is not in 200 state or failed to read REST response
     */
    private int getActiveSessionCount(AuthenticatedUser authenticatedUser) throws FrameworkException {

        int sessionCount;
        JSONObject paramMap = new JSONObject();
        paramMap.put(SessionValidationConstants.TABLE_NAME_TAG,
                SessionValidationConstants.ACTIVE_SESSION_TABLE_NAME);
        paramMap.put(SessionValidationConstants.QUERY_TAG,
                SessionValidationUtil.getQuery(authenticatedUser.getTenantDomain(),
                        authenticatedUser.getUserName(),
                        authenticatedUser.getUserStoreDomain()));
        if (log.isDebugEnabled()) {
            log.debug("JSON payload for retrieving data :" + paramMap.toString());
        }
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        StringEntity entity = new StringEntity(paramMap.toString(), ContentType.APPLICATION_JSON);
        HttpClient httpClient = httpClientBuilder.build();
        HttpPost request = new HttpPost(IdentityUtil.getProperty(SessionValidationConstants
                .TABLE_SEARCH_COUNT_CONFIG_NAMES));

        request = SessionValidationUtil.setAuthorizationHeader(request,
                IdentityUtil.getProperty(SessionValidationConstants.USERNAME_CONFIG_NAME),
                IdentityUtil.getProperty(SessionValidationConstants.CREDENTIAL_CONFIG_NAME));
        request.addHeader(SessionValidationConstants.CONTENT_TYPE_TAG, ContentType.APPLICATION_JSON.toString());
        request.setEntity(entity);
        try {
            HttpResponse response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(
                        response.getEntity().getContent(),
                        StandardCharsets.UTF_8.name()))) {
                    StringBuilder responseResult = new StringBuilder();
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        responseResult.append(line);
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Response from the data source :" + responseResult.toString());
                    }
                    sessionCount = parseInt(responseResult.toString());
                    return sessionCount;
                } catch (IOException e) {
                    throw new FrameworkException("Problem occurred while processing the HTTP Response ", e);
                } catch (NumberFormatException e) {
                    throw new FrameworkException("Problem occurred while parsing response result ", e);
                }
            } else {
                throw new FrameworkException("Failed to retrieve data from endpoint.Response status code :" +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new FrameworkException("Failed to execute the HTTP Post request", e);
        }
    }
}

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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jwt.SignedJWT;
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
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.AsyncReturn;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.cache.ChoreoAccessTokenCache;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.internal.ChoreoFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.secret.mgt.core.exception.SecretManagementException;
import org.wso2.carbon.identity.secret.mgt.core.model.ResolvedSecret;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_TIMEOUT;

/**
 * Implementation of the {@link CallChoreoFunction}
 */
public class CallChoreoFunctionImpl implements CallChoreoFunction {

    private static final Log LOG = LogFactory.getLog(CallChoreoFunctionImpl.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";
    private static final String AUTHORIZATION = "Authorization";
    private static final String GRANT_TYPE = "grant_type";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String URL_VARIABLE_NAME = "url";
    private static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
    private static final String CONSUMER_KEY_ALIAS_VARIABLE_NAME = "consumerKeyAlias";
    private static final String CONSUMER_SECRET_VARIABLE_NAME = "consumerSecret";
    private static final String CONSUMER_SECRET_ALIAS_VARIABLE_NAME = "consumerSecretAlias";
    private static final String SECRET_TYPE = "ADAPTIVE_AUTH_CALL_CHOREO";
    private static final char DOMAIN_SEPARATOR = '.';
    private static final String ACCESS_TOKEN_KEY = "access_token";
    private static final int HTTP_STATUS_OK = 200;
    private static final int HTTP_STATUS_UNAUTHORIZED = 401;
    private static final String ERROR_CODE_ACCESS_TOKEN_INACTIVE = "900901";
    private static final String CODE = "code";
    private static final String JWT_EXP_CLAIM = "exp";
    private final List<String> choreoDomains;
    private static final String BEARER = "Bearer ";
    private static final String BASIC = "Basic ";
    private static final int MAX_TOKEN_REQUEST_ATTEMPTS = 2;

    private final ChoreoAccessTokenCache choreoAccessTokenCache;

    public CallChoreoFunctionImpl() {

        this.choreoDomains = ConfigProvider.getInstance().getChoreoDomains();
        this.choreoAccessTokenCache = ChoreoAccessTokenCache.getInstance();
    }

    @Override
    public void callChoreo(Map<String, String> connectionMetaData, Map<String, Object> payloadData,
                           Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((authenticationContext, asyncReturn) -> {
            String epUrl = connectionMetaData.get(URL_VARIABLE_NAME);
            try {
                if (!isValidChoreoDomain(epUrl)) {
                    LOG.error("Provided Url does not contain a configured choreo domain. Invalid Url: " + epUrl);
                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                    return;
                }

                String tenantDomain = authenticationContext.getTenantDomain();
                AccessTokenResponseHandler accessTokenResponseHandler = new AccessTokenResponseHandler(
                        connectionMetaData, asyncReturn, authenticationContext, payloadData);
                String accessToken = choreoAccessTokenCache.getValueFromCache(ACCESS_TOKEN_KEY, tenantDomain);
                if (StringUtils.isNotEmpty(accessToken) && !isTokenExpired(accessToken)) {
                    accessTokenResponseHandler.callChoreoEndpoint(accessToken);
                } else {
                    LOG.debug("Requesting the access token from Choreo");
                    requestAccessToken(tenantDomain, connectionMetaData, accessTokenResponseHandler);
                }
            } catch (IllegalArgumentException e) {
                LOG.error("Invalid endpoint Url: " + epUrl, e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (IOException e) {
                LOG.error("Error while requesting access token from Choreo.", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (SecretManagementException e) {
                LOG.error("Error while resolving Choreo consumer key or secret.", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while invoking callChoreo.", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            }
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }

    /**
     * This method decodes access token and compare its expiry time with the current time to decide whether it's
     * expired.
     *
     * @param accessToken Access token which needs to be evaluated
     * @return A boolean value indicating whether the token is expired
     * @throws ParseException {@link ParseException}
     */
    private boolean isTokenExpired(String accessToken) throws ParseException {

        SignedJWT decodedToken = SignedJWT.parse(accessToken);
        Date expiryDate = (Date) decodedToken.getJWTClaimsSet().getClaim(JWT_EXP_CLAIM);
        LocalDateTime expiryTimestamp = LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().isAfter(expiryTimestamp);
    }

    public String getResolvedSecret(String name) throws SecretManagementException {

        ResolvedSecret responseDTO = ChoreoFunctionServiceHolder.getInstance().getSecretConfigManager()
                .getResolvedSecret(SECRET_TYPE, name);
        return responseDTO.getResolvedSecretValue();
    }

    private boolean isValidChoreoDomain(String url) {

        if (StringUtils.isBlank(url)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Provided url for domain restriction checking is null or empty.");
            }
            return false;
        }

        if (choreoDomains.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No domains configured for domain restriction. Allowing url by default. Url: " + url);
            }
            return true;
        }

        String domain;
        try {
            domain = getParentDomainFromUrl(url);
        } catch (URISyntaxException e) {
            LOG.error("Error while resolving the domain of the url: " + url, e);
            return false;
        }

        if (StringUtils.isEmpty(domain)) {
            LOG.error("Unable to determine the domain of the url: " + url);
            return false;
        }

        if (choreoDomains.contains(domain)) {
            return true;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Domain: " + domain + " extracted from url: " + url + " is not available in the " +
                    "configured choreo domain list: " + StringUtils.join(choreoDomains, ','));
        }

        return false;
    }

    private String getParentDomainFromUrl(String url) throws URISyntaxException {

        URI uri = new URI(url);
        String parentDomain = null;
        String domain = uri.getHost();
        String[] domainArr;
        if (domain != null) {
            domainArr = StringUtils.split(domain, DOMAIN_SEPARATOR);
            if (domainArr.length != 0) {
                parentDomain = domainArr.length == 1 ? domainArr[0] : domainArr[domainArr.length - 2];
                parentDomain = parentDomain.toLowerCase();
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Parent domain: " + parentDomain + " extracted from url: " + url);
        }
        return parentDomain;
    }

    /**
     * Performs the access token request using client credentials grant type.
     *
     * @param tenantDomain       The tenant domain which the request belongs to.
     * @param connectionMetaData A map which contains necessary info to make the token request.
     * @param futureCallback     The future callback that needs to be called after requesting the token.
     * @throws SecretManagementException {@link SecretManagementException}
     * @throws IOException               {@link IOException}
     * @throws FrameworkException        {@link FrameworkException}
     */
    private void requestAccessToken(String tenantDomain, Map<String, String> connectionMetaData,
                                    FutureCallback<HttpResponse> futureCallback) throws SecretManagementException,
                                    IOException, FrameworkException {

        HttpPost request = new HttpPost(ConfigProvider.getInstance().getChoreoTokenEndpoint());
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
        request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);

        String consumerKey;
        if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME))) {
            consumerKey = connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME);
        } else {
            String consumerKeyAlias = connectionMetaData.get(CONSUMER_KEY_ALIAS_VARIABLE_NAME);
            consumerKey = getResolvedSecret(consumerKeyAlias);
        }

        String consumerSecret;
        if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME))) {
            consumerSecret = connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME);
        } else {
            String consumerSecretAlias = connectionMetaData.get(CONSUMER_SECRET_ALIAS_VARIABLE_NAME);
            consumerSecret = getResolvedSecret(consumerSecretAlias);
        }

        request.setHeader(AUTHORIZATION, BASIC + Base64.getEncoder()
                .encodeToString((consumerKey + ":" + consumerSecret).getBytes(StandardCharsets.UTF_8)));

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        request.setEntity(new StringEntity(jsonObject.toJSONString()));

        CloseableHttpAsyncClient client = ChoreoFunctionServiceHolder.getInstance().getClientManager()
                .getClient(tenantDomain);
        client.execute(request, futureCallback);
    }

    private class AccessTokenResponseHandler implements FutureCallback<HttpResponse> {

        private final Map<String, String> connectionMetaData;
        private final AsyncReturn asyncReturn;
        private final AuthenticationContext authenticationContext;
        private final Map<String, Object> payloadData;
        private final Gson gson;
        private final AtomicInteger tokenRequestAttemptCount;

        public AccessTokenResponseHandler(Map<String, String> connectionMetaData,
                                          AsyncReturn asyncReturn,
                                          AuthenticationContext authenticationContext,
                                          Map<String, Object> payloadData) {

            this.connectionMetaData = connectionMetaData;
            this.asyncReturn = asyncReturn;
            this.authenticationContext = authenticationContext;
            this.payloadData = payloadData;
            this.gson = new GsonBuilder().create();
            this.tokenRequestAttemptCount = new AtomicInteger(0);
        }

        /**
         * The method to be called when access token request receives an HTTP response.
         *
         * @param httpResponse Received HTTP response.
         */
        @Override
        public void completed(HttpResponse httpResponse) {

            boolean isFailure = false;
            try {
                LOG.debug("Access token response received.");
                int responseCode = httpResponse.getStatusLine().getStatusCode();
                if (responseCode == 200) {
                    Type responseBodyType = new TypeToken<Map<String, String>>() { }.getType();
                    Map<String, String> responseBody = this.gson.fromJson(
                            EntityUtils.toString(httpResponse.getEntity()), responseBodyType);
                    String accessToken = responseBody.get(ACCESS_TOKEN_KEY);
                    if (accessToken != null) {
                        choreoAccessTokenCache.addToCache(ACCESS_TOKEN_KEY, accessToken,
                                this.authenticationContext.getTenantDomain());
                        callChoreoEndpoint(accessToken);
                    } else {
                        LOG.error("Token response does not contain an access token. Session data key: " +
                                authenticationContext.getContextIdentifier());
                        isFailure = true;
                    }
                } else {
                    LOG.error("Failed to retrieve access token from Choreo. Response Code: " + responseCode +
                            ". Session data key: " + authenticationContext.getContextIdentifier());
                    isFailure = true;
                }
            } catch (IOException e) {
                LOG.error("Failed to parse access token response to string. Session data key: " +
                        authenticationContext.getContextIdentifier(), e);
                isFailure = true;
            } catch (Exception e) {
                LOG.error("Error occurred while handling the token response from Choreo. Session data key: " +
                        authenticationContext.getContextIdentifier(), e);
                isFailure = true;
            }

            if (isFailure) {
                try {
                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                } catch (Exception e) {
                    LOG.error("Error while trying to return after handling the token request failure from Choreo. " +
                            "Session data key: " + authenticationContext.getContextIdentifier(), e);
                }
            }
        }

        /**
         * The method to be called when access token request fails.
         *
         * @param e Thrown exception.
         */
        @Override
        public void failed(Exception e) {

            LOG.error("Failed to request access token from Choreo for the session data key: " +
                    authenticationContext.getContextIdentifier(), e);
            try {
                String outcome = OUTCOME_FAIL;
                if ((e instanceof SocketTimeoutException) || (e instanceof ConnectTimeoutException)) {
                    outcome = OUTCOME_TIMEOUT;
                }
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), outcome);
            } catch (Exception ex) {
                LOG.error("Error while proceeding after failing to request access token for the session data key: " +
                        authenticationContext.getContextIdentifier(), e);
            }
        }

        /**
         * The method to be called when access token request canceled.
         */
        @Override
        public void cancelled() {

            LOG.error("Requesting access token from Choreo for the session data key: " +
                    authenticationContext.getContextIdentifier() + " is cancelled.");
            try {
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while proceeding after access token request to Choreo got cancelled " +
                        "for session data key: " + authenticationContext.getContextIdentifier(), e);
            }
        }

        /**
         * Invokes the Choreo API endpoint specified in the connection metadata using the provided access token.
         *
         * @param accessToken Access token that authorizes the request.
         */
        private void callChoreoEndpoint(String accessToken) {

            boolean isFailure = false;
            HttpPost request = new HttpPost(this.connectionMetaData.get(URL_VARIABLE_NAME));
            request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
            request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
            request.setHeader(AUTHORIZATION, BEARER + accessToken);

            try {
                JSONObject jsonObject = new JSONObject();
                jsonObject.putAll(this.payloadData);
                request.setEntity(new StringEntity(jsonObject.toJSONString()));
                CloseableHttpAsyncClient client = ChoreoFunctionServiceHolder.getInstance().getClientManager()
                        .getClient(this.authenticationContext.getTenantDomain());
                client.execute(request, new FutureCallback<HttpResponse>() {

                    @Override
                    public void completed(final HttpResponse response) {

                        try {
                            handleChoreoEndpointResponse(response);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after handling the response from Choreo call for " +
                                    "session data key: " + authenticationContext.getContextIdentifier(), e);
                        }
                    }

                    @Override
                    public void failed(final Exception ex) {

                        LOG.error("Failed to invoke Choreo for session data key: " +
                                authenticationContext.getContextIdentifier(), ex);
                        try {
                            String outcome = Constants.OUTCOME_FAIL;
                            if ((ex instanceof SocketTimeoutException) || (ex instanceof ConnectTimeoutException)) {
                                outcome = Constants.OUTCOME_TIMEOUT;
                            }
                            asyncReturn.accept(authenticationContext, Collections.emptyMap(), outcome);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after failed response from Choreo " +
                                    "call for session data key: " + authenticationContext.getContextIdentifier(), e);
                        }
                    }

                    @Override
                    public void cancelled() {

                        LOG.error("Invocation Choreo for session data key: " +
                                authenticationContext.getContextIdentifier() + " is cancelled.");
                        try {
                            asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after cancelled response from Choreo call for session " +
                                    "data key: " + authenticationContext.getContextIdentifier(), e);
                        }
                    }
                });
            } catch (UnsupportedEncodingException e) {
                LOG.error("Error while constructing request payload for calling choreo endpoint. session data key: " +
                        authenticationContext.getContextIdentifier(), e);
                isFailure = true;
            } catch (FrameworkException | IOException e) {
                LOG.error("Error while getting HTTP client for calling the choreo endpoint. session data key: " +
                        authenticationContext.getContextIdentifier(), e);
                isFailure = true;
            } catch (Exception e) {
                LOG.error("Error while calling Choreo endpoint. session data key: " +
                        authenticationContext.getContextIdentifier(), e);
                isFailure = true;
            }

            if (isFailure) {
                try {
                    this.asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                } catch (Exception e) {
                    LOG.error("Error while trying to return from Choreo call after an exception. session data key: " +
                            authenticationContext.getContextIdentifier(), e);
                }
            }
        }

        /**
         * Handles the response from the API call to the Choreo endpoint specified in the connection metadata.
         *
         * @param response HTTP response from the Choreo endpoint.
         * @throws FrameworkException {@link FrameworkException}
         */
        private void handleChoreoEndpointResponse(final HttpResponse response) throws FrameworkException {

            Type responseBodyType;
            try {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == HTTP_STATUS_OK) {
                    responseBodyType = new TypeToken<Map<String, Object>>() { }.getType();
                    Map<String, Object> successResponseBody = this.gson
                            .fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);
                    this.asyncReturn.accept(authenticationContext, successResponseBody, Constants.OUTCOME_SUCCESS);
                } else if (statusCode == HTTP_STATUS_UNAUTHORIZED) {
                    responseBodyType = new TypeToken<Map<String, String>>() { }.getType();
                    Map<String, String> responseBody = this.gson
                            .fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);

                    if (ERROR_CODE_ACCESS_TOKEN_INACTIVE.equals(responseBody.get(CODE))) {
                        handleExpiredToken();
                    } else {
                        LOG.warn("Received 401 response from Choreo. Session data key: " +
                                authenticationContext.getContextIdentifier());
                        this.asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                    }
                } else {
                    LOG.warn("Received non 200 response code from Choreo. Status Code: " + statusCode +
                            " Session data Key: " + authenticationContext.getContextIdentifier());
                    this.asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                }
            } catch (IOException e) {
                LOG.error("Error while reading response from Choreo call for session data key: " +
                        this.authenticationContext.getContextIdentifier(), e);
                this.asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while processing response from Choreo call for session data key: " +
                        this.authenticationContext.getContextIdentifier(), e);
                this.asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
            }
        }

        /**
         * Handles the scenario where the response from the Choreo API call is 401 Unauthorized due to an expired
         * token. The program will retry the token request flow until it exceeds the specified max request attempt
         * count.
         *
         * @throws SecretManagementException {@link SecretManagementException}
         * @throws IOException {@link IOException}
         * @throws FrameworkException {@link FrameworkException}
         */
        private void handleExpiredToken() throws SecretManagementException, IOException, FrameworkException {

            if (tokenRequestAttemptCount.get() < MAX_TOKEN_REQUEST_ATTEMPTS) {
                requestAccessToken(this.authenticationContext.getTenantDomain(), this.connectionMetaData, this);
                tokenRequestAttemptCount.incrementAndGet();
            } else {
                LOG.warn("Maximum token request attempt count exceeded for session data key: " +
                        this.authenticationContext.getContextIdentifier());
                tokenRequestAttemptCount.set(0);
                this.asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            }
        }
    }
}

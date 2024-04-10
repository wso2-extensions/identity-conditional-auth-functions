/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
package org.wso2.carbon.identity.conditional.auth.functions.http.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.identity.application.authentication.framework.AsyncReturn;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.conditional.auth.functions.http.cache.APIAccessTokenCache;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils.*;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;

/**
 * Implementation of the {@link AuthConfig}
 * This class is used to configure the client credential authentication.
 * The client credential is used to request the access token from the token endpoint.
 */
public class ClientCredentialAuthConfig implements AuthConfig {

    private static final Log LOG = LogFactory.getLog(ClientCredentialAuthConfig.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";
    private static final String TYPE_FORM_DATA = "application/x-www-form-urlencoded";
    private static final String AUTHORIZATION = "Authorization";
    private static final String GRANT_TYPE = "grant_type";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final Gson GSON = new GsonBuilder().create();
    private static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
    private static final String CONSUMER_SECRET_VARIABLE_NAME = "consumerSecret";
    private static final String TOKEN_ENDPOINT = "tokenEndpoint";
    private static final String SCOPES = "scope";
    private static final String ACCESS_TOKEN_KEY = "access_token";
    private static final String JWT_EXP_CLAIM = "exp";
    private static final String BEARER = "Bearer ";
    private static final String BASIC = "Basic ";
    private int maxRequestAttemptsForAPIEndpointTimeout;
    private APIAccessTokenCache apiAccessTokenCache;
    private String consumerKey;
    private String consumerSecret;
    private String scopes;
    private String tokenEndpoint;
    private AuthenticationContext authenticationContext;
    private AsyncReturn asyncReturn;

    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public void setAsyncReturn(AsyncReturn asyncReturn) {
        this.asyncReturn = asyncReturn;
    }

    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    public void setConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public String getConsumerSecret() {
        return consumerSecret;
    }

    public String getScopes() {
        return scopes;
    }

    @Override
    public HttpUriRequest applyAuth(HttpUriRequest request, AuthConfigModel authConfigModel)
            throws FrameworkException {

        maxRequestAttemptsForAPIEndpointTimeout = ConfigProvider.getInstance().
                getRequestRetryCount();
        this.apiAccessTokenCache = APIAccessTokenCache.getInstance();
        Map<String, Object> properties = authConfigModel.getProperties();
        validateRequiredProperties(properties);

        setConsumerKey(properties.get(CONSUMER_KEY_VARIABLE_NAME).toString());
        setConsumerSecret(properties.get(CONSUMER_SECRET_VARIABLE_NAME).toString());
        setTokenEndpoint(properties.get(TOKEN_ENDPOINT).toString());
        setScopes(properties.containsKey(SCOPES) ? properties.get(SCOPES).toString() : null);

        String accessToken = getAccessToken();
        if (accessToken == null) {
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                        DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.RECEIVE_TOKEN);
                diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                        .configParam(Constants.LogConstants.ConfigKeys.SUPPORTED_GRANT_TYPES,
                                GRANT_TYPE_CLIENT_CREDENTIALS)
                        .resultMessage("Failed to retrieve access token for the provided token endpoint.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            LOG.error("Failed to retrieve access token. Aborting request.");
            throw new FrameworkException("Failed to retrieve access token.");
        }
        request.setHeader(AUTHORIZATION, BEARER + accessToken);
        return request;
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

    /**
     * This method is used to get the access token from the token endpoint.
     *
     * @return Access token
     * @throws FrameworkException {@link FrameworkException}
     */
    private void validateRequiredProperties(Map<String, Object> properties) throws FrameworkException {

        if (!properties.containsKey(CONSUMER_KEY_VARIABLE_NAME) ||
                !properties.containsKey(CONSUMER_SECRET_VARIABLE_NAME) ||
                !properties.containsKey(TOKEN_ENDPOINT)) {
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            LOG.error("Required properties not defined. Aborting token request.");
            throw new FrameworkException("Missing required properties.");
        }
    }

    /**
     * This method is used to get the access token from the cache or request a new token from the token endpoint.
     *
     * @return Access token
     * @throws FrameworkException {@link FrameworkException}
     */
    private String getAccessToken() throws FrameworkException {
        String accessToken = apiAccessTokenCache.getValueFromCache(getConsumerKey(),
                authenticationContext.getTenantDomain());
        try {
            if (StringUtils.isNotEmpty(accessToken) && !isTokenExpired(accessToken)) {
                LOG.debug("Unexpired access token available in cache.");
                return accessToken;
            } else {
                // Attempt the first request for an access token
                LOG.info("Attempting initial access token request for session data key: " +
                        authenticationContext.getContextIdentifier());
                accessToken = requestAccessToken(); // Attempt to request a new token
                if (accessToken != null) {
                    return accessToken;
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_TOKEN);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .configParam(Constants.LogConstants.ConfigKeys.SUPPORTED_GRANT_TYPES,
                                    GRANT_TYPE_CLIENT_CREDENTIALS)
                            .resultMessage("Initial request failed, proceeding with retry attempts.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                // If the initial request fails, proceed with retry logic
                LOG.info("Initial request failed, proceeding with retry attempts.");
                return attemptAccessTokenRequest(maxRequestAttemptsForAPIEndpointTimeout);
            }
        } catch (ParseException e) {
            LOG.error("Error parsing token expiry.", e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid endpoint URL: " + getTokenEndpoint(), e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (Exception e) {
            LOG.error("Unexpected error during token acquisition.", e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        }
        return null;
    }

    /**
     * This method is used to attempt the access token request from the token endpoint.
     *
     * @param maxAttempts Maximum number of attempts to request the access token
     * @return Access token
     */
    private String attemptAccessTokenRequest(int maxAttempts) {

        int attemptCount = 0;

        while (++attemptCount < maxAttempts) {
            try {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_TOKEN);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .configParam(Constants.LogConstants.ConfigKeys.SUPPORTED_GRANT_TYPES,
                                    GRANT_TYPE_CLIENT_CREDENTIALS)
                            .resultMessage("Retrying token request for the provided token endpoint.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.info("Retrying token request for session data key: " +
                        this.authenticationContext.getContextIdentifier());
                String accessToken = requestAccessToken();
                if (accessToken != null) {
                    return accessToken;
                }
            } catch (IOException e) {
                LOG.error("Attempt " + attemptCount + " failed.", e);
            }

            LOG.info("Retrying token request. Attempt: " + attemptCount);
        }

        LOG.warn("Maximum token request attempts reached.");
        return null;
    }

    /**
     * This method is used to request the access token from the token endpoint.
     *
     * @return Access token
     * @throws IOException {@link IOException}
     */
    private String requestAccessToken() throws IOException {

        HttpPost request = new HttpPost(tokenEndpoint);
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
        request.setHeader(CONTENT_TYPE, TYPE_FORM_DATA);

        request.setHeader(AUTHORIZATION, BASIC + Base64.getEncoder()
                .encodeToString((getConsumerKey() + ":" + getConsumerSecret())
                        .getBytes(StandardCharsets.UTF_8)));

        List<BasicNameValuePair> bodyParams = new ArrayList<>();
        bodyParams.add(new BasicNameValuePair(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS));
        if (StringUtils.isNotEmpty(getScopes())) {
            bodyParams.add(new BasicNameValuePair(SCOPES, getScopes()));
        }
        request.setEntity(new UrlEncodedFormEntity(bodyParams));

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(ConfigProvider.getInstance().getConnectionTimeout())
                .setConnectionRequestTimeout(ConfigProvider.getInstance().getConnectionRequestTimeout())
                .setSocketTimeout(ConfigProvider.getInstance().getReadTimeout())
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();

        try (CloseableHttpClient client = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
             CloseableHttpResponse response = client.execute(request)) {

            int responseCode = response.getStatusLine().getStatusCode();
            if (responseCode >= 200 && responseCode < 300) {
                return processSuccessfulResponse(response);
            } else {
                LOG.error("Failed to retrieve access token. Response Code: " + responseCode + ". Session data key: " +
                        authenticationContext.getContextIdentifier());
            }
        } catch (ConnectTimeoutException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                        DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.RECEIVE_TOKEN);
                diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                        .configParam(Constants.LogConstants.ConfigKeys.SUPPORTED_GRANT_TYPES,
                                GRANT_TYPE_CLIENT_CREDENTIALS)
                        .resultMessage("Connection timed out while requesting access token.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            LOG.error("Connection timed out while requesting access token: " + tokenEndpoint, e);
        } catch (SocketTimeoutException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                        DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.RECEIVE_TOKEN);
                diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                        .configParam(Constants.LogConstants.ConfigKeys.SUPPORTED_GRANT_TYPES,
                                GRANT_TYPE_CLIENT_CREDENTIALS)
                        .resultMessage("Socket timed out while requesting access token.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            LOG.error("Socket timed out while requesting access token: " + tokenEndpoint, e);
        } catch (IOException e) {
            LOG.error("IO Exception while requesting access token: ", e);
        } catch (Exception e) {
            LOG.error("Unexpected error during token request: ", e);
        }
        return null;
    }

    /**
     * This method is used to process the successful response from the token endpoint.
     *
     * @param response {@link CloseableHttpResponse}
     * @return Access token
     * @throws IOException {@link IOException}
     */
    private String processSuccessfulResponse(CloseableHttpResponse response) throws IOException {

        Type responseBodyType = new TypeToken<Map<String, String>>(){}.getType();
        Map<String, String> responseBody = GSON.fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);
        String accessToken = responseBody.get(ACCESS_TOKEN_KEY);

        if (accessToken != null) {
            apiAccessTokenCache.addToCache(getConsumerKey(), accessToken,
                    this.authenticationContext.getTenantDomain());
            return accessToken;
        }
        LOG.error("Token response does not contain an access token. Session data key: " +
                authenticationContext.getContextIdentifier());
        return null;
    }
}

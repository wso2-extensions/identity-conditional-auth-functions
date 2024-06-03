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
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.conditional.auth.functions.http.util.HttpUtil.getRequestTokenActionId;

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
    private HttpUriRequest request;

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

    public HttpUriRequest getRequest() {
        return request;
    }

    public void setRequest(HttpUriRequest request) {
        this.request = request;
    }

    public String getScopes() {
        return scopes;
    }

    private enum RetryDecision {
        RETRY,
        NO_RETRY;

        public boolean shouldRetry() {
            return this == RETRY;
        }
    }

    @Override
    public HttpUriRequest applyAuth(HttpUriRequest request, AuthConfigModel authConfigModel)
            throws FrameworkException {

        setRequest(request);
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
                        getRequestTokenActionId(getRequest()));
                diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                        .inputParam(Constants.LogConstants.InputKeys.GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                        .configParam(Constants.LogConstants.ConfigKeys.MAX_REQUEST_ATTEMPTS,
                                maxRequestAttemptsForAPIEndpointTimeout)
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
                Pair<RetryDecision, String> retryDecision = requestAccessToken();
                if (retryDecision.getLeft().shouldRetry()) {
                    return attemptAccessTokenRequest(maxRequestAttemptsForAPIEndpointTimeout);
                } else {
                    return retryDecision.getRight();
                }
            }
        } catch (ParseException e) {
            LOG.error("Error parsing token expiry.", e);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                        DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        getRequestTokenActionId(getRequest()));
                diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                        .resultMessage("Failed to parse token expiry.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            LOG.error("Error parsing token expiry.", e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (IOException e) {
            LOG.error("Error while calling token endpoint. ", e);
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

        while (attemptCount < maxAttempts) {

            try {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            getRequestTokenActionId(getRequest()));
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .inputParam(Constants.LogConstants.InputKeys.GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                            .configParam(Constants.LogConstants.ConfigKeys.MAX_REQUEST_ATTEMPTS, maxAttempts)
                            .resultMessage("Retrying token request for the provided token endpoint. Attempt: " +
                                    attemptCount + ".")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    attemptCount++;
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.info("Retrying token request for session data key: " +
                        this.authenticationContext.getContextIdentifier() + ". Attempt: " + attemptCount);
                Pair<RetryDecision, String> retryDecision = requestAccessToken();
                if (!retryDecision.getLeft().shouldRetry()) {
                    return retryDecision.getRight();
                }
            } catch (IOException e) {
                LOG.error("Error while calling token endpoint. ", e);
            }
            attemptCount++;
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
    private Pair<RetryDecision, String> requestAccessToken() throws IOException {

        RetryDecision isRetry = RetryDecision.NO_RETRY;
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
            } else if (responseCode >= 300 && responseCode < 400) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            getRequestTokenActionId(getRequest()));
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .resultMessage("Token endpoint returned a redirection. Status code: " + responseCode)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.warn("Token endpoint returned a redirection. Status code: " + responseCode + ". Url: " +
                        tokenEndpoint);
                return Pair.of(RetryDecision.NO_RETRY, null);
            } else if (responseCode >= 400 && responseCode < 500) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            getRequestTokenActionId(getRequest()));
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .resultMessage("Token endpoint returned a client error. Status code: " + responseCode)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.warn("Token endpoint returned a client error. Status code: " + responseCode + ". Url: " +
                        tokenEndpoint);
                return Pair.of(RetryDecision.NO_RETRY, null);
            } else {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            getRequestTokenActionId(getRequest()));
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .resultMessage("Received unknown response from token endpoint. Status code: " +
                                    responseCode)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.error("Received unknown response from token endpoint. Status code: " + responseCode + ". Url: " +
                        tokenEndpoint);
                return Pair.of(RetryDecision.RETRY, null); // Server error, retry if attempts left
            }
        } catch (Exception e) {
            // Log the error based on its type
            if (e instanceof IllegalArgumentException) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            getRequestTokenActionId(getRequest()));
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .resultMessage("Invalid Url for token endpoint.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.error("Invalid Url: " + tokenEndpoint, e);
            } else if (e instanceof SocketTimeoutException || e instanceof ConnectTimeoutException) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            getRequestTokenActionId(getRequest()));
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .resultMessage("Request for the token endpoint timed out.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                isRetry = RetryDecision.RETRY; // Timeout, retry if attempts left
                LOG.error("Error while waiting to connect to " + tokenEndpoint, e);
            } else if (e instanceof IOException) {
                LOG.error("Error while calling token endpoint. ", e);
            } else {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            getRequestTokenActionId(getRequest()));
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                            .resultMessage("Received an error while invoking the token endpoint.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.error("Error while calling token endpoint. ", e);
            }
        }
        return Pair.of(isRetry, null);
    }

    /**
     * This method is used to process the successful response from the token endpoint.
     *
     * @param response {@link CloseableHttpResponse}
     * @return Access token
     * @throws IOException {@link IOException}
     */
    private Pair<RetryDecision, String> processSuccessfulResponse(CloseableHttpResponse response) throws IOException {

        Type responseBodyType = new TypeToken<Map<String, String>>(){}.getType();
        Map<String, String> responseBody = GSON.fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);
        String accessToken = responseBody.get(ACCESS_TOKEN_KEY);

        if (accessToken != null) {

            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                        DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        getRequestTokenActionId(getRequest()));
                diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.TOKEN_ENDPOINT, getTokenEndpoint())
                        .resultMessage("Received access token from the token endpoint.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            LOG.info("Received access token from the token endpoint. Session data key: " +
                    authenticationContext.getContextIdentifier());
            apiAccessTokenCache.addToCache(getConsumerKey(), accessToken,
                    this.authenticationContext.getTenantDomain());
            return Pair.of(RetryDecision.NO_RETRY, accessToken);
        }
        LOG.error("Token response does not contain an access token. Session data key: " +
                authenticationContext.getContextIdentifier());
        return Pair.of(RetryDecision.NO_RETRY, null);
    }
}

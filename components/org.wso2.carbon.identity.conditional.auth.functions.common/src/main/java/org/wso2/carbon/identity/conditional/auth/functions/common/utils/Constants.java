/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.conditional.auth.functions.common.utils;

public class Constants {

    public static final String OUTCOME_SUCCESS = "onSuccess";
    public static final String OUTCOME_FAIL = "onFail";
    public static final String OUTCOME_TIMEOUT = "onTimeout";
    public static final String GET = "GET";
    public static final String POST = "POST";

    public static final String RECEIVER_URL = "AdaptiveAuth.EventPublisher.ReceiverURL";
    public static final String HTTP_CONNECTION_TIMEOUT = "AdaptiveAuth.HTTPConnectionTimeout";
    public static final String HTTP_REQUEST_RETRY_COUNT = "AdaptiveAuth.HTTPRequestRetryCount";
    public static final String HTTP_READ_TIMEOUT = "AdaptiveAuth.HTTPReadTimeout";
    public static final String HTTP_CONNECTION_REQUEST_TIMEOUT = "AdaptiveAuth.HTTPConnectionRequestTimeout";
    public static final String AUTHENTICATION_ENABLED = "AdaptiveAuth.EventPublisher.BasicAuthentication.Enable";
    public static final String AUTHENTICATION_USERNAME = "AdaptiveAuth.EventPublisher.BasicAuthentication.Username";
    public static final String AUTHENTICATION_CREDENTIAL = "AdaptiveAuth.EventPublisher.BasicAuthentication.Password";
    public static final String HOSTNAME_VERIFIER = "AdaptiveAuth.EventPublisher.HostnameVerifier";

    public static final String CONNECTION_POOL_MAX_CONNECTIONS = "AdaptiveAuth.MaxTotalConnections";
    public static final String CONNECTION_POOL_MAX_CONNECTIONS_PER_ROUTE = "AdaptiveAuth.MaxTotalConnectionsPerRoute";

    public static final String CALL_CHOREO_HTTP_CONNECTION_TIMEOUT = "AdaptiveAuth.CallChoreo.HTTPConnectionTimeout";

    public static final String CALL_CHOREO_HTTP_CONNECTION_REQUEST_TIMEOUT = "AdaptiveAuth.CallChoreo.HTTPConnectionRequestTimeout";
    public static final String CALL_CHOREO_HTTP_READ_TIMEOUT = "AdaptiveAuth.CallChoreo.HTTPReadTimeout";
    public static final String CALL_CHOREO_TOKEN_REQUEST_RETRY_COUNT = "AdaptiveAuth.CallChoreo.TokenRequestRetryCount";
    public static final String CALL_CHOREO_API_REQUEST_RETRY_COUNT = "AdaptiveAuth.CallChoreo.ChoreoAPIRequestRetryCount";

    public static final String HTTP_FUNCTION_ALLOWED_DOMAINS = "AdaptiveAuth.HTTPFunctionAllowedDomains.Domain";
    public static final String CHOREO_DOMAINS = "AdaptiveAuth.ChoreoDomains.Domain";
    public static final String CHOREO_TOKEN_ENDPOINT = "AdaptiveAuth.ChoreoTokenEndpoint";

    /**
     * Define logging constants.
     */
    public static class LogConstants {

        public static final String ADAPTIVE_AUTH_SERVICE = "adaptive-auth-service";
        public static final String FAILED = "FAILED";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String REQUEST_TOKEN_HTTP_GET = "request-token-http-get";
            public static final String REQUEST_TOKEN_HTTP_POST = "request-token-http-post";
            public static final String INVOKE_API_HTTP_GET = "invoke-api-http-get";
            public static final String INVOKE_API_HTTP_POST = "invoke-api-http-post";
            public static final String VALIDATE_INPUT_PARAMS = "validate-input-parameters";
            public static final String UPDATE_USER_PASSWORD = "update-user-password";
        }

        /**
         * Define common and reusable Input keys for diagnostic logs.
         */
        public static class InputKeys {

            public static final String TOKEN_ENDPOINT = "token endpoint";
            public static final String API = "external api";
            public static final String GRANT_TYPE = "grant type";
        }

        /**
         * Define common and reusable Configuration keys for diagnostic logs.
         */
        public static class ConfigKeys {

            public static final String MAX_REQUEST_ATTEMPTS = "max request attempts";
        }
    }
}

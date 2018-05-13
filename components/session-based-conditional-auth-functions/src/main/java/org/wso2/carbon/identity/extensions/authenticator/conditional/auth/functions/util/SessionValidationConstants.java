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
package org.wso2.carbon.identity.extensions.authenticator.conditional.auth.functions.util;

/**
 * Class for storing Constants used in the session validation conditional authentication functions
 */
public class SessionValidationConstants {

    //Integer constants
    public static final int START_INDEX = 0;
    public static final int SESSION_COUNT_MAX = 100;
    //String constants
    public static final String USERNAME_TAG = "username";
    public static final String USER_STORE_TAG = "userstoreDomain";
    public static final String TENANT_DOMAIN_TAG = "tenantDomain";
    public static final String CONTENT_TYPE_TAG = "Content-type";
    public static final String AUTH_TYPE_KEY = "Basic ";
    public static final String ATTRIBUTE_SEPARATOR = ":";
    public static final String ACTIVE_SESSION_TABLE_NAME = "ORG_WSO2_IS_ANALYTICS_STREAM_ACTIVESESSIONS";
    public static final String TABLE_NAME_TAG = "tableName";
    public static final String QUERY_TAG = "query";
    public static final String AND_TAG = " AND ";
    public static final String SESSION_LIMIT_TAG = "sessionLimit";
    public static final String COUNT_TAG = "count";
    public static final String START_TAG = "start";
    public static final String TERMINATION_SESSION_ID = "sessionID";
    //Configuration names
    public static final String USERNAME_CONFIG_NAME = "SessionBasedValidation.Username";
    public static final String PASSWORD_CONFIG_NAME = "SessionBasedValidation.Password";
    public static final String TABLE_SEARCH_COUNT_CONFIG_NAMES = "SessionBasedValidation.TableSearchCountURL";
    public static final String TABLE_SEARCH_CONFIG_NAMES = "SessionBasedValidation.TableSearchURL";
    //JSONObject value tags
    public static final String VALUE_TAG = "values";
    public static final String SESSION_ID_TAG = "sessionId";
    public static final String TIMESTAMP_TAG = "timestamp";
    public static final String USER_AGENT_TAG = "userAgent";
    public static final String IP_TAG = "remoteIp";
    public static final String SERVICE_PROVIDER_TAG = "serviceProvider";
    public static final String SESSIONS_TAG = "sessions";
}

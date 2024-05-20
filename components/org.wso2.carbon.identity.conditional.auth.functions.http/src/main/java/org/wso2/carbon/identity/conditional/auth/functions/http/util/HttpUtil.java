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

import org.apache.http.client.methods.HttpUriRequest;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;

/**
 * Utility class for HTTP related operations.
 */
public class HttpUtil {

    /**
     * Get the invoke API Action ID based on the HTTP method.
     *
     * @param request HttpUriRequest
     * @return String
     */
    public static String getInvokeApiActionId(HttpUriRequest request) {

        String invokeApi;

        if (request.getMethod().equals(Constants.GET)) {
            invokeApi = Constants.LogConstants.ActionIDs.INVOKE_API_HTTP_GET;
        } else if (request.getMethod().equals(Constants.POST)) {
            invokeApi = Constants.LogConstants.ActionIDs.INVOKE_API_HTTP_POST;
        } else {
            invokeApi = "invoke-api";
        }

        return invokeApi;
    }
    
    /**
     * Get the request token Action ID based on the HTTP method.
     *
     * @param request HttpUriRequest
     * @return String
     */
    public static String getRequestTokenActionId(HttpUriRequest request) {
        String requestToken;
        if (request.getMethod().equals(Constants.GET)) {
            requestToken = Constants.LogConstants.ActionIDs.REQUEST_TOKEN_HTTP_GET;
        } else if (request.getMethod().equals(Constants.POST)) {
            requestToken = Constants.LogConstants.ActionIDs.REQUEST_TOKEN_HTTP_POST;
        } else {
            requestToken = "request-token";
        }
        return requestToken;
    }
}

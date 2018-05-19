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
 *
 */

package org.wso2.carbon.identity.conditional.auth.functions.cookie;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletResponse;

import java.util.Map;

/**
 * Function definition for add cookie to the context response.
 */
@FunctionalInterface
public interface SetCookieFunction {

    /**
     * Set the cookie in the response.
     *
     * @param response   response object
     * @param name       name of the cookie
     * @param value      value of the cookie
     * @param properties optional parameter of cookie with two additional parameters encrypt and sign.
     */
    void setCookie(JsServletResponse response, String name, String value, Map<String, Object> properties);
}

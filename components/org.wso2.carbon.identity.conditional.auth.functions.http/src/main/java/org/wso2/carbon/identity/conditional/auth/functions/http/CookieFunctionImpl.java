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

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import java.util.Map;
import java.util.Optional;
import javax.servlet.http.Cookie;

public class CookieFunctionImpl implements SetCookieFunction, GetCookieFunction {

    @Override
    public void setCookie(JsServletResponse response, String name, String value, Map<String, Object> properties) {


        Cookie cookie = new Cookie(name, value);
        Optional.ofNullable((String) properties.get(FrameworkConstants.JSAttributes.JS_COOKIE_DOMAIN))
                .ifPresent(cookie::setDomain);
        Optional.ofNullable((String) properties.get(FrameworkConstants.JSAttributes.JS_COOKIE_PATH))
                .ifPresent(cookie::setPath);
        Optional.ofNullable((String) properties.get(FrameworkConstants.JSAttributes.JS_COOKIE_COMMENT))
                .ifPresent(cookie::setComment);
        Optional.ofNullable((Integer) properties.get(FrameworkConstants.JSAttributes.JS_COOKIE_MAX_AGE))
                .ifPresent(cookie::setMaxAge);
        Optional.ofNullable((Integer) properties.get(FrameworkConstants.JSAttributes.JS_COOKIE_VERSION))
                .ifPresent(cookie::setVersion);
        Optional.ofNullable((Boolean) properties.get(FrameworkConstants.JSAttributes.JS_COOKIE_HTTP_ONLY))
                .ifPresent(cookie::setHttpOnly);
        Optional.ofNullable((Boolean) properties.get(FrameworkConstants.JSAttributes.JS_COOKIE_SECURE))
                .ifPresent(cookie::setSecure);
        // TODO: 16/05/18 encrypt and sign the value.
        response.addCookie(cookie);
    }

    @Override
    public String getCookieValue(JsServletRequest request, String name, Map<String, Object> properties) {

        Cookie[] cookies = request.getWrapped().getWrapped().getCookies();
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                // TODO: 16/05/18 decrypt and validate the value.
                return cookie.getValue();
            }
        }
        return null;
    }
}

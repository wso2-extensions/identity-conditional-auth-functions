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

import org.apache.axiom.om.util.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.core.util.SignatureUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletResponse;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.HTTPConstants;

import java.util.Map;
import java.util.Optional;
import javax.servlet.http.Cookie;

/**
 * Implementation of the setCookie and getCookieValue functions.
 */
public class CookieFunctionImpl implements SetCookieFunction, GetCookieFunction {

    private static final Log log = LogFactory.getLog(CookieFunctionImpl.class);

    @Override
    public void setCookie(JsServletResponse response, String name, String value, Map<String, Object> properties) {

        boolean sign = Optional.ofNullable((Boolean) properties.get(HTTPConstants.SIGN)).orElse(false);
        boolean encrypt = Optional.ofNullable((Boolean) properties.get(HTTPConstants.ENCRYPT)).orElse(false);
        String signature = null;
        if (sign) {
            try {
                signature = Base64.encode(SignatureUtil.doSignature(value));
            } catch (Exception e) {
                log.error("Error occurred when signing the cookie value.", e);
                return;
            }
        }
        if (encrypt) {
            try {
                value = CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(Base64.decode(value));
            } catch (CryptoException e) {
                log.error("Error occurred when encrypting the cookie value.", e);
                return;
            }
        }
        JSONObject cookieValueJson = new JSONObject();
        try {
            cookieValueJson.put(HTTPConstants.VALUE, value);
            cookieValueJson.put(HTTPConstants.SIGNATURE, signature);
        } catch (JSONException e) {
            return;
        }
        String cookieValue = cookieValueJson.toString();

        cookieValue = Base64.encode((cookieValue.getBytes(Charsets.UTF_8)));
        Cookie cookie = new Cookie(name, cookieValue);
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
        response.addCookie(cookie);
    }

    @Override
    public String getCookieValue(JsServletRequest request, String name, Map<String, Object> properties) {

        Cookie[] cookies = request.getWrapped().getWrapped().getCookies();
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                boolean validateSignature = Optional.ofNullable((Boolean) properties.get(HTTPConstants.VALIDATE_SIGN))
                        .orElse(false);
                boolean decrypt = Optional.ofNullable((Boolean) properties.get(HTTPConstants.DECRYPT))
                        .orElse(false);
                JSONObject cookieValueJSON;
                try {
                    JSONParser jsonParser = new JSONParser();
                    cookieValueJSON = (JSONObject) jsonParser.parse(new String(Base64.decode(cookie.getValue()),
                            Charsets.UTF_8));
                } catch (ParseException e) {
                    log.error("Error occurred when converting cookie value to JSON.", e);
                    return null;
                }
                String valueString = (String) cookieValueJSON.get(HTTPConstants.VALUE);
                if (decrypt) {
                    try {
                        valueString = Base64.encode(CryptoUtil.getDefaultCryptoUtil()
                                .base64DecodeAndDecrypt(valueString));
                    } catch (CryptoException e) {
                        log.error("Error occurred when decrypting the cookie value.", e);
                        return null;
                    }
                }
                if (validateSignature) {
                    byte[] signature = Base64.decode((String) cookieValueJSON.get(HTTPConstants.SIGNATURE));
                    try {
                        boolean isValid = SignatureUtil.validateSignature(valueString, signature);
                        if (!isValid) {
                            log.error("Cookie signature didn't matched with the cookie value.");
                            return null;
                        }
                    } catch (Exception e) {
                        log.error("Error occurred when validating signature of the cookie value.", e);
                        return null;
                    }
                }
                return valueString;
            }
        }
        return null;
    }
}

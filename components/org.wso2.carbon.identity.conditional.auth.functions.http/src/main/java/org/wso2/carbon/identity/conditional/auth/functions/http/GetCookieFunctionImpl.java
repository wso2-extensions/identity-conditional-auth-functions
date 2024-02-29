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

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.core.util.SignatureUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.HTTPConstants;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.Cookie;

/**
 * Implementation of GetCookieFunction.
 */
public class GetCookieFunctionImpl implements GetCookieFunction {

    private static final Log log = LogFactory.getLog(GetCookieFunctionImpl.class);
    private static final String ENABLE_ADAPTIVE_SCRIPT_COOKIE_LEGACY_MODE = "enableAdaptiveScriptCookieLegacyMode";

    @Override
    @HostAccess.Export
    public String getCookieValue(JsServletRequest request, Object... params) {

        Map<String, Object> properties = null;
        if (params.length == 0 || params.length > 2) {
            return null;
        }
        if (params.length == 2) {
            if (params[1] instanceof Map) {
                properties = (Map<String, Object>) params[1];
            }
        }
        String name = (String) params[0];
        Cookie[] cookies = request.getWrapped().getWrapped().getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
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

                if (properties != null) {
                    boolean validateSignature = Optional.ofNullable((Boolean) properties.get(
                            HTTPConstants.VALIDATE_SIGN)).orElse(false);
                    boolean decrypt = Optional.ofNullable((Boolean) properties.get(HTTPConstants.DECRYPT))
                            .orElse(false);
                    if (decrypt) {
                        try {
                            if (Boolean.parseBoolean(System.getProperty(ENABLE_ADAPTIVE_SCRIPT_COOKIE_LEGACY_MODE))) {
                                valueString = Base64.encode(CryptoUtil.getDefaultCryptoUtil()
                                        .base64DecodeAndDecrypt(valueString));
                            } else {
                                valueString = new String(CryptoUtil.getDefaultCryptoUtil()
                                        .base64DecodeAndDecrypt(valueString), StandardCharsets.UTF_8);
                            }
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
                }
                return valueString;
            }
        }
        return null;
    }
}

/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.user;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;

import java.text.ParseException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Function to check whether email received from microsoft account is verified.
 */
public class MicrosoftEmailVerificationFunctionImpl implements MicrosoftEmailVerificationFunction {

    private static final Log LOG = LogFactory.getLog(MicrosoftEmailVerificationFunctionImpl.class);
    private static final String ISSUER = "iss";
    private static final String ID_TOKEN = "id_token";
    private static final String VERIFIED_PRIMARY_EMAIL = "verified_primary_email";
    private static final String EMAIL = "email";
    private static final String MICROSOFT_ROOT_ISSUER =
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";

    @Override
    @HostAccess.Export
    public boolean checkMicrosoftEmailVerification(JsAuthenticationContext context) {

        if (context.getWrapped().getParameter(ID_TOKEN) == null) {
            return false;
        }
        String idToken = context.getWrapped().getParameter(ID_TOKEN).toString();
        Map<String, Object> idTokenClaims = getIdTokenClaims(idToken);
        // Handle whether the user is logged in with a Microsoft account which is not verified.
        String issuer = (String) idTokenClaims.get(ISSUER);
        String userEmail = (String) idTokenClaims.get(EMAIL);
        if (!MICROSOFT_ROOT_ISSUER.equals(issuer)) {
            Object verifiedPrimaryEmail = idTokenClaims.get(VERIFIED_PRIMARY_EMAIL);
            if (userEmail != null && (verifiedPrimaryEmail == null || (verifiedPrimaryEmail instanceof List &&
                    (((List<?>) verifiedPrimaryEmail).isEmpty() ||
                            !((List<?>) verifiedPrimaryEmail).contains(userEmail))))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get the claims from the ID token.
     *
     * @param idToken ID token.
     * @return Map of claims.
     */
    private Map<String, Object> getIdTokenClaims(String idToken) {

        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parse(new String(decoded)).entrySet();
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }
}

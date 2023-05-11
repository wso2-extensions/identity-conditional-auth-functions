package org.wso2.carbon.identity.conditional.auth.functions.user;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;

import java.text.ParseException;
import java.util.*;

public class CheckVerifiedEmailFunctionImpl implements CheckVerifiedEmailFunction {

    private static final Log log = LogFactory.getLog(CheckVerifiedEmailFunctionImpl.class);
    private static final String ISSUER = "iss";
    private static final String ID_TOKEN = "id_token";
    private static final String VERIFIED_PRIMARY_EMAIL = "verified_primary_email";
    private static final String EMAIL = "email";
    private static final String MICROSOFT_ROOT_ISSUER =
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";

    @Override
    public boolean checkVerifiedEmail(JsAuthenticationContext context) {

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
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }
}

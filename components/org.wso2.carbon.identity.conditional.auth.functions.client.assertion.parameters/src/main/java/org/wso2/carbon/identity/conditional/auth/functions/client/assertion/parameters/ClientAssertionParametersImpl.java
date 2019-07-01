package org.wso2.carbon.identity.conditional.auth.functions.client.assertion.parameters;

import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ClientAssertionParametersImpl implements ClientAssertionParameters {

    @Override
    public Object getAuthenticationRequestParamValue(String clientAssertion, String parameterName,
                                                     boolean isParameterInBody) throws FrameworkException {

        String[] tokens;
        if (clientAssertion != null) {
            tokens = clientAssertion.split("\\.");
            if (tokens.length == 3) {
                JSONObject decodedAssertion = null;
                if (isParameterInBody) {
                    decodedAssertion = getDecodedAssertion(tokens[1]);
                } else {
                    decodedAssertion = getDecodedAssertion(tokens[0]);
                }
                if (decodedAssertion != null && decodedAssertion.has(parameterName)) {
                    Object parameterValue =  decodedAssertion.get(parameterName);
                    if(parameterValue instanceof String) {
                        return decodedAssertion.getString(parameterName);
                    } else if(parameterValue instanceof JSONObject) {
                        return decodedAssertion.getJSONObject(parameterName).toString();
                    } else if(parameterValue instanceof JSONArray) {
                        return decodedAssertion.getJSONArray(parameterName).toString();
                    }
                }
            }
        }
        return new Object();
    }

    public JSONObject getDecodedAssertion(String encodedAssertion) {

        String decodedAssertion = new String(Base64.getDecoder().decode(encodedAssertion.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8);
        return new JSONObject(decodedAssertion);
    }

}

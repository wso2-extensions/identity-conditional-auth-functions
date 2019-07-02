package org.wso2.carbon.identity.conditional.auth.functions.client.assertion.parameters;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ClientAssertionParametersImpl implements ClientAssertionParameters {

    private static final Log log = LogFactory.getLog(ClientAssertionParametersImpl.class);

    /**
     * @param clientAssertion   jwt assertion
     * @param parameterName     parameter to be retrieved from jwt
     * @param isParameterInBody whether parameter to be retrieved is in jwt body
     * @return String representation of the decoded value of the parameter
     * @throws FrameworkException
     */
    @Override
    public Object getValueFromDecodedAssertion(String clientAssertion, String parameterName,
                                               boolean isParameterInBody) throws FrameworkException {

        String[] tokens;
        if (clientAssertion != null) {
            tokens = clientAssertion.split("\\.");
            if (tokens.length == 3) {
                if (log.isDebugEnabled()) {
                    log.debug("Valid assertion found: " + clientAssertion);
                }
                JSONObject decodedAssertion = null;
                if (isParameterInBody) {
                    decodedAssertion = getDecodedAssertion(tokens[1]);
                } else {
                    decodedAssertion = getDecodedAssertion(tokens[0]);
                }
                if (decodedAssertion != null && decodedAssertion.has(parameterName)) {
                    //check whether the requested parameter is a json object, json array or a string
                    Object parameterValue = decodedAssertion.get(parameterName);
                    if (parameterValue instanceof String) {

                        if (log.isDebugEnabled()) {
                            log.debug("Requested parameter: " + decodedAssertion.getString(parameterName));
                        }
                        return decodedAssertion.getString(parameterName);
                    } else if (parameterValue instanceof JSONObject) {

                        if (log.isDebugEnabled()) {
                            log.debug("Requested parameter: " + decodedAssertion.getJSONObject(parameterName));
                        }
                        return decodedAssertion.getJSONObject(parameterName).toString();
                    } else if (parameterValue instanceof JSONArray) {

                        if (log.isDebugEnabled()) {
                            log.debug("Requested parameter: " + decodedAssertion.getJSONArray(parameterName));
                        }
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

/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.conditional.auth.functions.jwt.decode;

import com.nimbusds.jose.JWSObject;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * Represents javascript function provided in conditional authentication to decode a jwt assertion and retrieve
 * a particular value in the assertion
 */
public class JwtDecodeImpl implements JwtDecode {

    private static final Log log = LogFactory.getLog(JwtDecodeImpl.class);

    /**
     * @param clientAssertion      jwt assertion
     * @param parameterName        parameter to be retrieved from jwt
     * @param isParameterInPayload whether parameter to be retrieved is in jwt body
     * @return String representation of the decoded value of the parameter
     * @throws FrameworkException
     */
    @Override
    @HostAccess.Export
    public String getValueFromDecodedAssertion(String clientAssertion, String parameterName,
                                               boolean isParameterInPayload) throws FrameworkException {

        if (clientAssertion != null) {

            JSONObject decodedAssertion = null;
            try {
                decodedAssertion = getDecodedAssertion(clientAssertion, isParameterInPayload);
            } catch (ParseException e) {
                log.error("Error while parsing the client assertion", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Decoded assertion: " + decodedAssertion);
            }
            if (decodedAssertion != null && decodedAssertion.containsKey(parameterName)) {
                return decodedAssertion.get(parameterName).toString();
            }
        }
        return "";
    }

    public JSONObject getDecodedAssertion(String encodedAssertion, boolean isParameterInPayload) throws ParseException {

        JWSObject plainObject;
        Map<String, Object> resultMap;

        plainObject = JWSObject.parse(encodedAssertion);
        if (isParameterInPayload) {
            resultMap = plainObject.getPayload().toJSONObject();
        } else {
            resultMap = plainObject.getHeader().toJSONObject();
        }
        if (resultMap == null) {
            return null;
        }
        JSONObject jsonObject = new JSONObject(resultMap);
        recursivelyConvertToJSONObject(jsonObject);
        return jsonObject;
    }

    private void recursivelyConvertToJSONObject(JSONObject jsonObject) {

        for (String key : jsonObject.keySet()) {
            Object value = jsonObject.get(key);
            if (value instanceof Map) {
                JSONObject child = new JSONObject((Map<String, Object>) value);
                recursivelyConvertToJSONObject(child);
                jsonObject.put(key, child);
            } else if (value instanceof List) {
                JSONArray jsonArray = new JSONArray();
                jsonArray.addAll((List<?>) value);
                recursivelyConvertToJSONArray(jsonArray);
                jsonObject.put(key, jsonArray);
            }
        }
    }

    private void recursivelyConvertToJSONArray(JSONArray jsonArray) {

        for (int i = 0; i < jsonArray.size(); i++) {
            Object element = jsonArray.get(i);
            if (element instanceof Map) {
                JSONObject child = new JSONObject((Map<String, Object>) element);
                recursivelyConvertToJSONObject(child);
                jsonArray.set(i, child);
            } else if (element instanceof List) {
                JSONArray childArray = new JSONArray();
                childArray.addAll((List<?>) element);
                recursivelyConvertToJSONArray(childArray);
                jsonArray.set(i, childArray);
            }
        }
    }

}

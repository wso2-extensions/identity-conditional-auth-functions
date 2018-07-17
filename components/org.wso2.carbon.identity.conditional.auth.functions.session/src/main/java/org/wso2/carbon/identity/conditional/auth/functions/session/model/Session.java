/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.conditional.auth.functions.session.model;

import org.json.JSONObject;

/**
 * Model class to store details about a active sessions of user.
 */
public class Session {

    private String sessionId;
    private String timeStamp;
    private String userAgent;
    private String ipAddress;
    private String serviceProvider;

    public String getSessionId() {
        return sessionId;
    }
    /**
     * Constructor of the model class.
     *
     * @param sessionId       ID of the session
     * @param startTimeStamp  Timestamp  representing the creation time of session
     * @param userAgent       user agent for the session
     * @param ipAddress       ip address of the user
     * @param serviceProvider service provider of the session
     */
    public Session(String sessionId, String startTimeStamp, String userAgent, String ipAddress, String serviceProvider) {

        this.sessionId = sessionId;
        this.timeStamp = startTimeStamp;
        this.userAgent = userAgent;
        this.ipAddress = ipAddress;
        this.serviceProvider = serviceProvider;
    }

    /**
     * Method for retrieving session details as a JSON Object.
     *
     * @return A JSON Object with session details
     */
    public JSONObject toJSONObject() {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("sessionID", sessionId);
        jsonObject.put("timestamp", timeStamp);
        jsonObject.put("userAgent", userAgent);
        jsonObject.put("ipAddress", ipAddress);
        jsonObject.put("serviceProvider", serviceProvider);
        return jsonObject;
    }
}

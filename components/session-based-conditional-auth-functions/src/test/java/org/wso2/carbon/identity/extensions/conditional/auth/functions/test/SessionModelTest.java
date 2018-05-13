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
package org.wso2.carbon.identity.extensions.conditional.auth.functions.test;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.extensions.authenticator.conditional.auth.functions.model.Session;

/**
 * Contains methods for testing Session Model class methods
 */
public class SessionModelTest {

    @Test
    public void testGetJSONObject() {

        String sessionId = TestUtils.getRandomString(10, true, true);
        String timeStamp = TestUtils.getRandomString(10, false, true);
        String userAgent = TestUtils.getRandomString(10, true, true);
        String ipAddress = TestUtils.getRandomString(8, true, true);
        String serviceProvider = TestUtils.getRandomString(8, true, false);
        Session session = new Session(sessionId, timeStamp, userAgent, ipAddress, serviceProvider);
        String actual = "{" +
                "\"ipAddress\":\"" + ipAddress + "\"" +
                ",\"serviceProvider\":\"" + serviceProvider + "\"," +
                "\"userAgent\":\"" + userAgent + "\"," +
                "\"sessionID\":\"" + sessionId + "\"," +
                "\"timestamp\":\"" + timeStamp + "\"" +
                "}";
        Assert.assertEquals(actual, session.getJSONObject().toString());
    }
}

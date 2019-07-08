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
package org.wso2.carbon.identity.conditional.auth.functions.client.assertion.parameters.test;

import net.minidev.json.JSONArray;
import org.mockito.Spy;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.testng.Assert;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.client.assertion.parameters.ClientAssertionParametersImpl;

import static org.mockito.MockitoAnnotations.initMocks;

public class ClientAssertionParametersTest {

    @Spy
    ClientAssertionParametersImpl authenticationParameters;

    @BeforeClass
    public void setup() {

        initMocks(this);
    }

    String clientAssertion = "eyJraWQiOiJDelVlMWVjTUt5a0hMaFFBQVR6RkJ1ZE9qMFkiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImNya" +
            "XQiOlsiYjY0IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pYXQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lzcyIsImh0dHA" +
            "6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIl19.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo4MjQzL3Rva2VuIiwibWF4X2FnZSI6ODY0" +
            "MDAsInNjb3BlIjoicGF5bWVudHMgb3BlbmlkIiwiZXhwIjoxOTU0NzA4NzEwLCJjbGFpbXMiOnsiaWRfdG9rZW4iOnsiYWNyIjp7InZhbH" +
            "VlcyI6WyJ1cm46b3BlbmJhbmtpbmc6cHNkMjpjYSIsInVybjpvcGVuYmFua2luZzpwc2QyOnNjYSJdLCJlc3NlbnRpYWwiOnRydWV9LCJv" +
            "cGVuYmFua2luZ19pbnRlbnRfaWQiOnsidmFsdWUiOiI4NjVlNmZhMy1jOTcwLTQzZjYtYTdmMy0wN2E4ZDdkMmU2NmQiLCJlc3NlbnRpYW" +
            "wiOnRydWV9fSwidXNlcmluZm8iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7InZhbHVlIjoiODY1ZTZmYTMtYzk3MC00M2Y2LWE3ZjMt" +
            "MDdhOGQ3ZDJlNjZkIiwiZXNzZW50aWFsIjp0cnVlfX19LCJpc3MiOiJnbGxEZV80ZVd0TlZqanhtc0ZuY3VNRGZuQm9hIiwicmVzcG9uc2" +
            "VfdHlwZSI6ImNvZGUgaWRfdG9rZW4iLCJyZWRpcmVjdF91cmkiOiJodHRwczovL3d3dy5hbWF6b24uY29tIiwic3RhdGUiOiIwcE4wTkJU" +
            "SGN2Iiwibm9uY2UiOiJqQlhoT21PS0NCIiwiY2xpZW50X2lkIjoiZ2xsRGVfNGVXdE5Wamp4bXNGbmN1TURmbkJvYSJ9.AQiVpjprn1dX-" +
            "fk3j71MxY8pHZuVtW0am-_y_3Xz5rDkPcEjPm6TZ-rsK-ir2JeVEuPZYELf6orm_zRX5biQ9_TqhmzI1PWOeiCEUq21mQIbi_o2uxt42Nv" +
            "dsiQ2OTN-mHLLnB3HgV9XAGI2x8WmWpFCdZUc1gF2jLehS-2Fukb4wweR0yfhBb8JsLvUpiiyJJnp66L6Igr-yZMZa46BwcTWL9zGMZANX" +
            "UlCI-WuhHHFHsM8Yz64oRTVJA3tBbEmcI0y14bZhMQxin8mJ5OBZRx6gMSEzlxYYbby8mFkwFOWKOb0xVfQdB1sJAVYnjzOFpLVAbDAreL" +
            "bcTrSxCmPHg";

    @Test
    public void testRetrieveAuthParamString() throws FrameworkException {

        String decodedValue = (String) authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "state", true);
        Assert.assertEquals(decodedValue, "0pN0NBTHcv");

    }

    @Test
    public void testRetrieveAuthParamJSONObject() throws FrameworkException {

        String decodedValue = (String) authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "claims", true);
        String claims = "{\"id_token\":{\"acr\":{\"values\":[\"urn:openbanking:psd2:ca\",\"urn:openbanking:psd2:sca\"]" +
                ",\"essential\":true},\"openbanking_intent_id\":{\"value\":\"865e6fa3-c970-43f6-a7f3-07a8d7d2e66d\"," +
                "\"essential\":true}},\"userinfo\":{\"openbanking_intent_id\":{\"value\"" +
                ":\"865e6fa3-c970-43f6-a7f3-07a8d7d2e66d\",\"essential\":true}}}";
        Assert.assertEquals(decodedValue, claims);
    }

    @Test
    public void testRetrieveAuthParamJSONArray() throws FrameworkException {

        String decodedValue = (String) authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "crit", false);
        String crit = "[b64, http://openbanking.org.uk/iat, http://openbanking.org.uk/tan, http://openbanking.org.uk/iss]";
        Assert.assertEquals(decodedValue, crit);
    }

    @Test
    public void testWrongParameter() throws FrameworkException {

        Object decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "scope", false);
        Assert.assertFalse(decodedValue instanceof String);
    }

}

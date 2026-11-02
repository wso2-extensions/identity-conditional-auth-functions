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
package org.wso2.carbon.identity.conditional.auth.functions.jwt.decode.test;

import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.mockito.Spy;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.testng.Assert;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.jwt.decode.JwtDecodeImpl;

import static org.mockito.MockitoAnnotations.initMocks;

public class JwtDecodeTest {

    @Spy
    JwtDecodeImpl authenticationParameters;

    @BeforeClass
    public void setup() {

        initMocks(this);
    }

    String clientAssertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkN6VWUxZWNNS3lrSExoUUFBVHpGQnVkT2owWSIsImNy" +
            "aXQiOlsiYjY0IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pYXQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lzcyIsImh0dH" +
            "A6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIl0sIng1YyI6WyJNSUlCa1RDQi13SUpBTC4uLmNlcnQxIiwiTUlJQmtUQ0Itd0lKQUwuLi5j" +
            "ZXJ0MiJdLCJwZXJtaXNzaW9ucyI6WyJSZWFkQWNjb3VudHNCYXNpYyIsIlJlYWRCYWxhbmNlcyJdfQ.eyJhdWQiOiJodHRwczovL2xvY2" +
            "FsaG9zdDo4MjQzL3Rva2VuIiwibWF4X2FnZSI6ODY0MDAsInNjb3BlIjoicGF5bWVudHMgb3BlbmlkIiwiZXhwIjoxOTU0NzA4NzEwLCJj" +
            "bGFpbXMiOnsiaWRfdG9rZW4iOnsiYWNyIjp7InZhbHVlcyI6WyJ1cm46b3BlbmJhbmtpbmc6cHNkMjpjYSIsInVybjpvcGVuYmFua2luZz" +
            "pwc2QyOnNjYSJdLCJlc3NlbnRpYWwiOnRydWV9LCJvcGVuYmFua2luZ19pbnRlbnRfaWQiOnsidmFsdWUiOiI4NjVlNmZhMy1jOTcwLTQz" +
            "ZjYtYTdmMy0wN2E4ZDdkMmU2NmQiLCJlc3NlbnRpYWwiOnRydWV9fSwidXNlcmluZm8iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7In" +
            "ZhbHVlIjoiODY1ZTZmYTMtYzk3MC00M2Y2LWE3ZjMtMDdhOGQ3ZDJlNjZkIiwiZXNzZW50aWFsIjp0cnVlfX19LCJpc3MiOiJnbGxEZV80" +
            "ZVd0TlZqanhtc0ZuY3VNRGZuQm9hIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUgaWRfdG9rZW4iLCJyZWRpcmVjdF91cmkiOiJodHRwczovL3" +
            "d3dy5hbWF6b24uY29tIiwic3RhdGUiOiIwcE4wTkJUSGN2Iiwibm9uY2UiOiJqQlhoT21PS0NCIiwiY2xpZW50X2lkIjoiZ2xsRGVfNGVX" +
            "dE5Wamp4bXNGbmN1TURmbkJvYSIsImFjY291bnRzIjpbeyJhY2NvdW50X2lkIjoiYWNjLTAwMSIsInBlcm1pc3Npb25zIjpbIlJlYWRCYX" +
            "NpYyIsIlJlYWREZXRhaWwiXSwibWV0YWRhdGEiOnsiY3VycmVuY3kiOiJHQlAiLCJ0eXBlIjoiQ3VycmVudCJ9fSx7ImFjY291bnRfaWQi" +
            "OiJhY2MtMDAyIiwicGVybWlzc2lvbnMiOlsiUmVhZEJhc2ljIl0sIm1ldGFkYXRhIjp7ImN1cnJlbmN5IjoiRVVSIiwidHlwZSI6IlNhdm" +
            "luZ3MifX1dfQ.AQiVpjprn1dX-fk3j71MxY8pHZuVtW0am-_y_3Xz5rDkPcEjPm6TZ-rsK-ir2JeVEuPZYELf6orm" +
            "_zRX5biQ9_TqhmzI1PWOeiCEUq21mQIbi_o2uxt42NvdsiQ2OTN-mHLLnB3HgV9XAGI2x8WmWpFCdZUc1gF2jLehS-2Fukb4wweR0yfhBb" +
            "8JsLvUpiiyJJnp66L6Igr-yZMZa46BwcTWL9zGMZANXUlCI-WuhHHFHsM8Yz64oRTVJA3tBbEmcI0y14bZhMQxin8mJ5OBZRx6gMSEzlxY" +
            "Ybby8mFkwFOWKOb0xVfQdB1sJAVYnjzOFpLVAbDAreLbcTrSxCmPHg";

    @Test
    public void testRetrieveAuthParamString() throws FrameworkException {

        String decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "state", true);
        Assert.assertEquals(decodedValue, "0pN0NBTHcv");

    }

    @Test
    public void testRetrieveAuthParamJSONObject() throws FrameworkException {

        String decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "claims", true);
        String claims = "{\"id_token\":{\"acr\":{\"values\":[\"urn:openbanking:psd2:ca\",\"urn:openbanking:psd2:sca\"]" +
                ",\"essential\":true},\"openbanking_intent_id\":{\"value\":\"865e6fa3-c970-43f6-a7f3-07a8d7d2e66d\"," +
                "\"essential\":true}},\"userinfo\":{\"openbanking_intent_id\":{\"value\"" +
                ":\"865e6fa3-c970-43f6-a7f3-07a8d7d2e66d\",\"essential\":true}}}";
        Assert.assertEquals(decodedValue, claims);
    }

    @Test
    public void testRetrieveAuthParamJSONArray() throws FrameworkException, ParseException {

        String decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "accounts", true);
        String accounts = "[{\"metadata\":{\"currency\":\"GBP\",\"type\":\"Current\"},\"account_id\":\"acc-001\"," +
                "\"permissions\":[\"ReadBasic\",\"ReadDetail\"]},{\"metadata\":{\"currency\":\"EUR\",\"type\":\"Savings\"}," +
                "\"account_id\":\"acc-002\",\"permissions\":[\"ReadBasic\"]}]";

        JSONParser parser = new JSONParser(JSONParser.DEFAULT_PERMISSIVE_MODE);
        JSONArray decodedArray = (JSONArray) parser.parse(decodedValue);
        JSONArray accountsArray = (JSONArray) parser.parse(accounts);
        Assert.assertEquals(decodedArray, accountsArray);
    }

    @Test
    public void testRetrieveHeaderCritArray() throws FrameworkException {

        String decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "crit", false);
        String crit = "[b64, http://openbanking.org.uk/iat, http://openbanking.org.uk/tan, http://openbanking.org.uk/iss]";
        Assert.assertEquals(decodedValue, crit);
    }

    @Test
    public void testRetrieveHeaderX5cArray() throws FrameworkException {

        String decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "x5c", false);
        Assert.assertEquals(decodedValue, "[MIIBkTCB-wIJAL...cert1, MIIBkTCB-wIJAL...cert2]");
    }

    @Test
    public void testRetrieveHeaderCustomArray() throws FrameworkException {

        String decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "permissions", false);
        Assert.assertEquals(decodedValue, "[\"ReadAccountsBasic\",\"ReadBalances\"]");
    }

    @Test
    public void testWrongParameter() throws FrameworkException {

        String decodedValue = authenticationParameters.getValueFromDecodedAssertion(clientAssertion,
                "scope", false);
        Assert.assertTrue(decodedValue.isEmpty());
    }

}

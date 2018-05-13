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

import org.mockito.Mock;
import org.mockito.Spy;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.extensions.authenticator.conditional.auth.functions.function.GetSessionDataFunction;
import org.wso2.carbon.identity.extensions.authenticator.conditional.auth.functions.function.IsWithinSessionLimitFunction;
import org.wso2.carbon.identity.extensions.authenticator.conditional.auth.functions.function.KillSessionFunction;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * Contains methods for testing Conditional authentication functions
 */

public class ConditionalAuthFunctionTest {

    @Mock
    KillSessionFunction killSessionFunction;
    @Spy
    IsWithinSessionLimitFunction isWithinSessionLimitFunction;
    @Spy
    GetSessionDataFunction getSessionDataFunction;
    @Mock
    JsAuthenticationContext jsAuthenticationContext;
    @Mock
    AuthenticationContext authenticationContext;
    @Mock
    AuthenticatedUser authenticatedUser;

    @BeforeClass
    public void setup() {

        initMocks(this);
    }

    //Test for isWithinSessionLimitFunction with mock authenticatedUser
    @Test(expectedExceptions = {AuthenticationFailedException.class, NullPointerException.class})
    public void testIsWithinSessionLimitFunction() throws AuthenticationFailedException {

        when(jsAuthenticationContext.getWrapped()).thenReturn(authenticationContext);
        when(authenticationContext.getLastAuthenticatedUser()).thenReturn(authenticatedUser);
        String sessionLimit = String.valueOf(TestUtils.getRandomInt(0, 10));
        Map<String, String> map = new HashMap<>();
        map.put("sessionLimit", sessionLimit);
        isWithinSessionLimitFunction.validate(jsAuthenticationContext, map);
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testGetSessionData() throws AuthenticationFailedException {

        when(jsAuthenticationContext.getWrapped()).thenReturn(authenticationContext);
        when(authenticationContext.getLastAuthenticatedUser()).thenReturn(authenticatedUser);
        Map<String, String> map = new HashMap<>();
        getSessionDataFunction.getData(jsAuthenticationContext, map);

    }

}

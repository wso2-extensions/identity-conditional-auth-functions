/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.utils;

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.core.common.User;

import java.lang.reflect.Field;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@WithCarbonHome
@WithRealmService(injectToSingletons = {FrameworkServiceDataHolder.class})
public class ResolveMultiAttributeLoginIdentifierFunctionImplTest {

    private ResolveMultiAttributeLoginIdentifierFunctionImpl testFunction;

    @Mock
    private MultiAttributeLoginService multiAttributeLoginServiceMock;

    @BeforeClass
    public void setUp() throws NoSuchFieldException, IllegalAccessException {

        testFunction = new ResolveMultiAttributeLoginIdentifierFunctionImpl();
        initMocks(this);

        Field frameworkServiceDataHolder = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolder.setAccessible(true);
        FrameworkServiceDataHolder instance = (FrameworkServiceDataHolder) frameworkServiceDataHolder.get(null);
        instance.setMultiAttributeLoginService(multiAttributeLoginServiceMock);
    }

    @DataProvider(name = "loginIdentifierProvider")
    public Object[][] loginIdentifierProvider() {

        return new Object[][]{
                {false, "username", "username"},
                {true, "username", "username"},
                {true, "test@wso2.com", "username"}
        };
    }

    @Test (dataProvider = "loginIdentifierProvider")
    public void testResolveMultiAttributeLoginIdentifier(boolean multiAttributeLoginEnabled,
                                                         String loginIdentifier, String username) {

        ResolvedUserResult userResult = new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.SUCCESS);

        if (multiAttributeLoginEnabled) {
            User user = new User("123456", username, username);
            userResult.setUser(user);
        } else {
            userResult.setResolvedStatus(ResolvedUserResult.UserResolvedStatus.FAIL);
        }

        when(multiAttributeLoginServiceMock.isEnabled(anyString())).thenReturn(multiAttributeLoginEnabled);
        when(multiAttributeLoginServiceMock.resolveUser(loginIdentifier, "carbon.super")).thenReturn(userResult);

        String result = testFunction.resolveMultiAttributeLoginIdentifier(loginIdentifier, "carbon.super");

        if (multiAttributeLoginEnabled) {
            Assert.assertNotNull(result);
            Assert.assertEquals(result, username);
        } else {
            Assert.assertNull(result);
        }
    }
}

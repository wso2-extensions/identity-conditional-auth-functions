/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mockStatic;

/**
 * Test class for IsAnyOfTheRolesAssignedToUserFunctionImpl.
 */
@WithCarbonHome
public class IsAnyOfTheRolesAssignedToUserTest {

    @BeforeClass
    public void setUp() {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super", true);
    }

    @AfterClass
    public void tearDown() {

        PrivilegedCarbonContext.destroyCurrentContext();
    }

    @DataProvider(name = "isUserInCurrentTenantDataProvider")
    public Object[][] getIsUserInCurrentTenantData() {

        return new Object[][]{
                {true, "t2.com", "t1.com", "t2.com", false},
                {false, "t2.com", "t1.com", "carbon.super", false},
        };
    }

    @Test(dataProvider = "isUserInCurrentTenantDataProvider")
    public void testCrossTenantScenarioReturnsFalse(boolean isTenantQualified, String authContextTenantDomain,
            String userTenantDomain, String carbonContextTenantDomain, boolean expected) throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(carbonContextTenantDomain, true);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain(userTenantDomain);
        authenticatedUser.setUserStoreDomain("PRIMARY");

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(authContextTenantDomain);

        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(context, authenticatedUser);
        List<String> roles = Arrays.asList("role1", "role2");

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(isTenantQualified);
            IsAnyOfTheRolesAssignedToUserFunctionImpl isAnyOfTheRolesAssignedToUserFunction =
                    new IsAnyOfTheRolesAssignedToUserFunctionImpl();
            boolean result = isAnyOfTheRolesAssignedToUserFunction.IsAnyOfTheRolesAssignedToUser(jsUser, roles);
            Assert.assertEquals(result, expected, "Cross-tenant role-assignment check should return " + expected);
        }
    }
}

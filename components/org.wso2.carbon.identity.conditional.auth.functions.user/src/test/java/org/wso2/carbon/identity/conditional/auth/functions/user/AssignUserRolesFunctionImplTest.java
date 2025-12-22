/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.openjdk.nashorn.JsOpenJdkNashornAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.Arrays;
import java.util.List;

/**
 * Test class for AssignUserRolesFunctionImpl.
 */
public class AssignUserRolesFunctionImplTest {

    @BeforeMethod
    public void setUp() {

        initPrivilegedCarbonContext();
    }

    @Test
    public void testCrossTenantScenarioReturnsFalse() {

        // Create authenticated user with tenant domain
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("tenant1.com");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        JsAuthenticatedUser jsUser = new JsOpenJdkNashornAuthenticatedUser(authenticatedUser);
        
        List<String> roles = Arrays.asList("role1", "role2");

        // Create a custom implementation that simulates cross-tenant scenario
        AssignUserRolesFunctionImpl assignUserRolesFunction = new AssignUserRolesFunctionImpl();
        boolean result = assignUserRolesFunction.assignUserRoles(jsUser, roles);

        // Should return false for cross-tenant operation
        Assert.assertFalse(result, "Should return false for cross-tenant operation");
    }

    private void initPrivilegedCarbonContext() {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super", true);
    }
}

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

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsUserSession;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * Unit tests for GetUserSessionsFunctionImpl class.
 */
@WithCarbonHome
@WithRealmService(injectToSingletons = {UserFunctionsServiceHolder.class, IdentityTenantUtil.class,
        FrameworkServiceDataHolder.class})
public class GetUserSessionsFunctionImplTest {

    private static final String TEST_USER_NAME = "testUser";
    private static final String TENANT_DOMAIN_CARBON_SUPER = "carbon.super";
    private static final String USER_STORE_DOMAIN_PRIMARY = "PRIMARY";
    private static final String TEST_USER_ID_123 = "test-user-id-123";
    private static final String TEST_USER_ID_456 = "test-user-id-456";
    private static final String TEST_USER_ID_ORG_123 = "test-user-id-org-123";
    private static final String TEST_USER_ID_ORG_456 = "test-user-id-org-456";
    private static final String ORG_ID_123 = "org123";
    private static final String ORG_TENANT_DOMAIN = "org.tenant.com";
    private static final String INVALID_ORG = "invalidOrg";
    private static final String ORG_NOT_FOUND_MESSAGE = "Organization not found";

    @Mock
    private UserSessionManagementService userSessionManagementService;
    @Mock
    private OrganizationManager organizationManager;
    private GetUserSessionsFunctionImpl getUserSessionsFunction;

    @BeforeMethod
    public void setUp() {

        initMocks(this);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(TENANT_DOMAIN_CARBON_SUPER, true);

        getUserSessionsFunction = new GetUserSessionsFunctionImpl();
        UserFunctionsServiceHolder.getInstance().setUserSessionManagementService(userSessionManagementService);
        UserFunctionsServiceHolder.getInstance().setOrganizationManager(organizationManager);
    }

    @AfterMethod
    public void tearDown() {

        PrivilegedCarbonContext.destroyCurrentContext();
    }

    @Test
    public void testGetUserSessionsSuccess() throws Exception {

        // Create test user.
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_CARBON_SUPER);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN_PRIMARY);
        authenticatedUser.setUserId(TEST_USER_ID_123);

        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(authenticatedUser);

        // Create mock user sessions.
        List<UserSession> mockSessions = new ArrayList<>();
        UserSession session1 = mock(UserSession.class);
        UserSession session2 = mock(UserSession.class);
        mockSessions.add(session1);
        mockSessions.add(session2);

        // Mock the session management service.
        when(userSessionManagementService.getSessionsByUserId(TEST_USER_ID_123, TENANT_DOMAIN_CARBON_SUPER))
                .thenReturn(mockSessions);

        // Execute the function.
        List<JsUserSession> result = getUserSessionsFunction.getUserSessions(jsUser);

        // Verify results.
        Assert.assertNotNull(result);
        Assert.assertEquals(result.size(), 2);
    }

    @Test
    public void testGetUserSessionsWithEmptyResult() throws Exception {

        // Create test user.
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_CARBON_SUPER);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN_PRIMARY);
        authenticatedUser.setUserId(TEST_USER_ID_456);

        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(authenticatedUser);

        // Mock empty session list.
        when(userSessionManagementService.getSessionsByUserId(TEST_USER_ID_456, TENANT_DOMAIN_CARBON_SUPER))
                .thenReturn(new ArrayList<>());

        // Execute the function.
        List<JsUserSession> result = getUserSessionsFunction.getUserSessions(jsUser);

        // Verify results.
        Assert.assertNotNull(result);
        Assert.assertEquals(result.size(), 0);
    }

    @Test
    public void testGetUserSessionsWithOrganization() throws Exception {

        // Create test user with accessing organization.
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_CARBON_SUPER);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN_PRIMARY);
        authenticatedUser.setUserId(TEST_USER_ID_ORG_123);
        authenticatedUser.setAccessingOrganization(ORG_ID_123);

        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(authenticatedUser);

        // Mock organization manager.
        when(organizationManager.resolveTenantDomain(ORG_ID_123)).thenReturn(ORG_TENANT_DOMAIN);

        // Create mock user sessions
        List<UserSession> mockSessions = new ArrayList<>();
        UserSession session = mock(UserSession.class);
        mockSessions.add(session);

        // Mock the session management service with resolved tenant domain.
        when(userSessionManagementService.getSessionsByUserId(TEST_USER_ID_ORG_123, ORG_TENANT_DOMAIN))
                .thenReturn(mockSessions);

        // Execute the function.
        List<JsUserSession> result = getUserSessionsFunction.getUserSessions(jsUser);

        // Verify results.
        Assert.assertNotNull(result);
        Assert.assertEquals(result.size(), 1);
    }

    @Test
    public void testGetUserSessionsWithOrganizationManagementException() throws Exception {

        // Create test user with accessing organization.
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER_NAME);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN_CARBON_SUPER);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN_PRIMARY);
        authenticatedUser.setUserId(TEST_USER_ID_ORG_456);
        authenticatedUser.setAccessingOrganization(INVALID_ORG);

        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(authenticatedUser);

        // Mock organization manager to throw exception.
        when(organizationManager.resolveTenantDomain(INVALID_ORG))
                .thenThrow(new OrganizationManagementException(ORG_NOT_FOUND_MESSAGE));

        // Execute the function.
        List<JsUserSession> result = getUserSessionsFunction.getUserSessions(jsUser);
        Assert.assertNull(result);
    }
}

/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithH2Database(files = "dbscripts/h2.sql")
@WithRealmService(injectToSingletons = {UserFunctionsServiceHolder.class, IdentityTenantUtil.class,
        FrameworkServiceDataHolder.class})
public class IsMemberOfAnyOfGroupsFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @WithRealmService
    private RealmService realmService;

    @BeforeClass
    protected void setUpMocks() {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super", true);
    }

    @AfterClass
    protected void tearDown() {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
        PrivilegedCarbonContext.destroyCurrentContext();
    }

    @BeforeMethod
    protected void setUp() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("isMemberOfAnyOfGroups",
                new IsMemberOfAnyOfGroupsFunctionImpl());
        UserRealm userRealm = realmService.getTenantUserRealm(-1234);
        userRealm.getUserStoreManager().addRole("students",
                new String[]{"user1", "user2"}, null);
        userRealm.getUserStoreManager().addRole("teachers",
                new String[]{"user1", "user3"}, null);
    }

    @Test(dataProvider = "isMemberOfAnyOfGroupsDataProvider")
    public void testHasAnyOfTheRoles(String user, boolean steppedUp) throws Exception {

        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator", user, Collections.emptyMap());

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("isMemberOfAnyOfGroups-test-sp.xml",
                this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);

        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertNotNull(context.getSelectedAcr());
        assertEquals(Boolean.parseBoolean(context.getSelectedAcr()), steppedUp);

    }

    @DataProvider(name = "isMemberOfAnyOfGroupsDataProvider")
    public Object[][] getIsMemberOfAnyOfGroupsData() {

        return new Object[][]{
                {"user1", true},
                {"user2", true},
                {"user3", true},
                {"user4", false}
        };
    }

    @Test
    public void testCrossTenantScenarioReturnsFalse() {

        // Create authenticated user with tenant domain
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("tenant1.com");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(authenticatedUser);
        List<String> groups = Arrays.asList("group1", "group2");

        // Create a custom implementation that simulates cross-tenant scenario
        IsMemberOfAnyOfGroupsFunctionImpl isMemberOfAnyOfGroupsFunction = new IsMemberOfAnyOfGroupsFunctionImpl();
        boolean result = isMemberOfAnyOfGroupsFunction.isMemberOfAnyOfGroups(jsUser, groups);

        // Should return false for cross-tenant operation
        Assert.assertFalse(result, "Should return false for cross-tenant operation");
    }
}

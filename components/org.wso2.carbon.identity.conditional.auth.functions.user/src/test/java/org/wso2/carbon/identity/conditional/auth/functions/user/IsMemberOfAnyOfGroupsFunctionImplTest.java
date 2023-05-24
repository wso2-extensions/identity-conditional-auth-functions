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

import org.testng.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.dao.CacheBackedIdPMgtDAO;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.sql.Connection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithH2Database(files = "dbscripts/h2.sql")
@WithRealmService(injectToSingletons = {UserFunctionsServiceHolder.class, IdentityTenantUtil.class,
        FrameworkServiceDataHolder.class})
public class IsMemberOfAnyOfGroupsFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @WithRealmService
    private RealmService realmService;

    @BeforeMethod
    protected void setUp() throws Exception {

        super.setUp();
        sequenceHandlerRunner.registerJsFunction("isMemberOfAnyOfGroups",
                new IsMemberOfAnyOfGroupsFunctionImpl());
        UserRealm userRealm = realmService.getTenantUserRealm(-1234);
        userRealm.getUserStoreManager().addRole("students",
                new String[]{"user1", "user2"}, null);
        userRealm.getUserStoreManager().addRole("teachers",
                new String[]{"user1", "user3"}, null);
    }

    @AfterMethod
    public void tearDown() {

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
                {"user1", true}
//                {"user2", true},
//                {"user3", true},
//                {"user4", false}
        };
    }

    @Test(dataProvider = "isMemberOfAnyOfGroupsDataProviderForFederatedUser")
    public void testHasAnyOfTheRolesForFederatedUsers(String user, Map<String, String> claims,
                                                      boolean steppedUp) throws Exception {

        mockIdentityProviderManager();

//        mockStatic(FrameworkUtils.class);
//        when(FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");

        sequenceHandlerRunner.addSubjectAuthenticatorForFederatedUser("HwkMockAuthenticator", user,
                claims, "HwkMockIdp");

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

    private void mockIdentityProviderManager() throws InvocationTargetException, IdentityProviderManagementException {

        CacheBackedIdPMgtDAO cacheBackedIdPMgtDAO = mock(CacheBackedIdPMgtDAO.class);
        Field daoField = null;
        try {
            daoField = IdentityProviderManager.class.getDeclaredField("dao");
            daoField.setAccessible(true);
            daoField.set(IdentityProviderManager.getInstance(), cacheBackedIdPMgtDAO);

            IdentityProvider idp = getMockIdentityProvider();
            when(cacheBackedIdPMgtDAO.getIdPByName(any(Connection.class), anyString(), anyInt(), anyString()))
                    .thenReturn(idp);
        } catch (NoSuchFieldException e) {
            throw new InvocationTargetException(e, "Could not inject mock objects to test runtime");
        } catch (IllegalAccessException e) {
            throw new InvocationTargetException(e, "Failed to inject mock objects to test runtime");
        } catch (IdentityProviderManagementException e) {
            throw new IdentityProviderManagementException("Error while getting identity provider");
        }
    }

    private IdentityProvider getMockIdentityProvider() {

        ClaimMapping claimMapping = ClaimMapping.build("http://wso2.org/claims/applicationRoles",
                "groups", "", true);
        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setClaimMappings(new ClaimMapping[]{claimMapping});

        IdentityProvider idp = new IdentityProvider();
        idp.setId(UUID.randomUUID().toString());
        idp.setIdentityProviderName("HwkMockIdp");
        idp.setEnable(true);
        idp.setClaimConfig(claimConfig);

        return idp;
    }

    @DataProvider(name = "isMemberOfAnyOfGroupsDataProviderForFederatedUser")
    public Object[][] getIsMemberOfAnyOfGroupsDataForFederatedUser() {

        Map<String, String> claimSet1 = new HashMap<String,String>();;
        claimSet1.put("groups", "teachers, students");

        Map<String, String> claimSet2 = new HashMap<String,String>();;
        claimSet2.put("groups", "students");

        Map<String, String> claimSet3 = new HashMap<String,String>();;
        claimSet2.put("groups", "employee");

        Map<String, String> claimSet4 = new HashMap<String,String>();;
        claimSet2.put("groups", "teachers");

        return new Object[][]{
                {"user1", claimSet1, true},
                {"user2", claimSet2, true},
                {"user3", claimSet3, false},
                {"user4", claimSet3, true}
        };
    }
}

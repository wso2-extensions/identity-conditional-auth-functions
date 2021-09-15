/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.choreo;

import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.CacheBackedLongWaitStatusDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.LongWaitStatusDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.store.LongWaitStatusStoreService;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.script.AuthenticationScriptConfig;
import org.wso2.carbon.identity.common.testng.InjectMicroservicePort;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithMicroService;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.internal.ChoreoFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class CallChoreoFunctionImplTest extends JsSequenceHandlerAbstractTest {

    private static final String FAILED = "FAILED";

    @WithRealmService
    private RealmService realmService;

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeMethod
    protected void setUp() throws Exception {

        super.setUp();

        sequenceHandlerRunner.registerJsFunction("callChoreo", new CallChoreoFunctionImpl());
        UserRealm userRealm = realmService.getTenantUserRealm(-1234);
        userRealm.getUserStoreManager().addRole("admin", new String[]{"admin", "test_user"}, null);
    }

    @DataProvider(name = "choreoEps")
    public Object[][] getChoreoEps() {

        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "choreoEps")
    public void testCallChoreo(boolean isValidChoreDomain) throws JsTestException,
            NoSuchFieldException, IllegalAccessException, FrameworkException {

        FunctionsDataHolder functionsDataHolder = Mockito.mock(FunctionsDataHolder.class);
        Field functionsDataHolderInstance = FunctionsDataHolder.class.getDeclaredField("instance");
        functionsDataHolderInstance.setAccessible(true);
        functionsDataHolderInstance.set(null, functionsDataHolder);

        Field frameworkServiceDataHolderInstance = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolderInstance.setAccessible(true);
        FrameworkServiceDataHolder availableInstance = (FrameworkServiceDataHolder) frameworkServiceDataHolderInstance
                .get(null);
        ClientManager clientManager = new ClientManager();
        ChoreoFunctionServiceHolder.getInstance().setClientManager(clientManager);

        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        availableInstance.setLongWaitStatusStoreService(longWaitStatusStoreService);

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("risk-test-sp.xml",
                this);
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                sp1.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig authenticationScriptConfig = localAndOutboundAuthenticationConfig
                .getAuthenticationScriptConfig();
        String content = authenticationScriptConfig.getContent();
        if (isValidChoreDomain) {
            // Setting localhost as the valid domain as
            // the unit test is calling a mock local endpoint.
            setChoreoDomain("localhost");
        } else {
            setChoreoDomain("abc");
        }
        String newContent = String.format(content, microServicePort);
        authenticationScriptConfig.setContent(newContent);
        localAndOutboundAuthenticationConfig.setAuthenticationScriptConfig(authenticationScriptConfig);
        sp1.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);
        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        if (isValidChoreDomain) {
            assertNotNull(context.getSelectedAcr());
            assertEquals(context.getSelectedAcr(), "1", "Expected acr value not found");
        } else {
            assertEquals(context.getSelectedAcr(), FAILED, "Expected the request to fail");
        }
    }

    private void setChoreoDomain(String domain) {

        ConfigProvider.getInstance().getChoreoDomains().clear();
        ConfigProvider.getInstance().getChoreoDomains().add(domain);
    }

    @POST
    @Path("/dummyurl")
    @Consumes("application/json")
    @Produces("application/json")
    public Map<String, String> choreoReceiver(Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        response.put("riskScore", "1");
        return response;
    }
}

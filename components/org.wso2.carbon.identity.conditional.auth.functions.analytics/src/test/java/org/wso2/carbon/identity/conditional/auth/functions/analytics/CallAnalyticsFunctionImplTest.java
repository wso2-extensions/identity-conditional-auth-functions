/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.analytics;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.graalvm.polyglot.HostAccess;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsParameters;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.CacheBackedLongWaitStatusDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.LongWaitStatusDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.store.LongWaitStatusStoreService;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.script.AuthenticationScriptConfig;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.InjectMicroservicePort;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithMicroService;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.ResponseValidator;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
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
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class CallAnalyticsFunctionImplTest extends JsSequenceHandlerAbstractTest {

public static final String ANALYTICS_SERVICE_CHECK_PAYLOAD = "/analytics-service-check-payload";
    public static final String ANALYTICS_PAYLOAD_JSON = "analytics-payload.json";
    public static final String ANALYTICS_PAYLOAD_TEST_SP = "analytics-payload-test-sp.xml";
    public static final String ANALYTICS_PAYLOAD = "analytics-payload.json";

    @WithRealmService
    private RealmService realmService;

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeClass
    protected void setUpMocks() {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
    }

    @AfterClass
    protected void tearDown() {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @BeforeMethod
    protected void setUp() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("callAnalytics", new CallAnalyticsFunctionImpl());
        UserRealm userRealm = realmService.getTenantUserRealm(-1234);
        userRealm.getUserStoreManager().addRole("admin", new String[]{"admin", "test_user"}, null);
    }

    @Test
    public void testRiskScore() throws JsTestException, NoSuchFieldException,
            IllegalAccessException,
            IdentityGovernanceException {

        IdentityGovernanceService identityGovernanceService = Mockito.mock(IdentityGovernanceService.class);
        FunctionsDataHolder functionsDataHolder = Mockito.mock(FunctionsDataHolder.class);
        Mockito.when(functionsDataHolder.getIdentityGovernanceService()).thenReturn(identityGovernanceService);
        Property property = new Property();
        property.setValue("http://localhost:" + microServicePort);
        Mockito.when(identityGovernanceService.getConfiguration(new String[]{AnalyticsEngineConfigImpl.RECEIVER},
                "test_domain")).thenReturn(new Property[]{property});

        Field functionsDataHolderInstance = FunctionsDataHolder.class.getDeclaredField("instance");
        functionsDataHolderInstance.setAccessible(true);
        functionsDataHolderInstance.set(null, functionsDataHolder);

        Field frameworkServiceDataHolderInstance = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolderInstance.setAccessible(true);
        FrameworkServiceDataHolder availableInstance = (FrameworkServiceDataHolder)frameworkServiceDataHolderInstance.get(null);

        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        availableInstance.setLongWaitStatusStoreService(longWaitStatusStoreService);

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("risk-test-sp.xml", this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);

        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        assertNotNull(context.getSelectedAcr());
        assertEquals(context.getSelectedAcr(), "1", "Expected acr value not found");
    }

    @DataProvider(name = "payloadType")
    public Object[][] getCookieValues() {

        return new Object[][]{
                {"serializedComprehensivePayload"},
                {"nonSerializedComprehensivePayload"}
        };
    }

    @Test(dataProvider = "payloadType")
    public void testAnalyticsPayload(String payloadType)
            throws JsTestException, IdentityGovernanceException, NoSuchFieldException, IllegalAccessException {

        sequenceHandlerRunner.registerJsFunction("validateResponse", new ResponseValidatorImpl());
        IdentityGovernanceService identityGovernanceService = Mockito.mock(IdentityGovernanceService.class);
        FunctionsDataHolder functionsDataHolder = Mockito.mock(FunctionsDataHolder.class);
        Mockito.when(functionsDataHolder.getIdentityGovernanceService()).thenReturn(identityGovernanceService);
        Property property = new Property();
        property.setValue("http://localhost:" + microServicePort);
        Mockito.when(identityGovernanceService.getConfiguration(new String[]{AnalyticsEngineConfigImpl.RECEIVER},
                "test_domain")).thenReturn(new Property[]{property});

        Field functionsDataHolderInstance = FunctionsDataHolder.class.getDeclaredField("instance");
        functionsDataHolderInstance.setAccessible(true);
        functionsDataHolderInstance.set(null, functionsDataHolder);

        Field frameworkServiceDataHolderInstance = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolderInstance.setAccessible(true);
        FrameworkServiceDataHolder availableInstance = (FrameworkServiceDataHolder)frameworkServiceDataHolderInstance.get(null);

        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        availableInstance.setLongWaitStatusStoreService(longWaitStatusStoreService);

        AuthenticationContext context = getAuthenticationContextForPayloadTest(payloadType);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        assertNotNull(context.getSelectedAcr());
        assertEquals(context.getSelectedAcr(), "1", "Expected acr value not found");

    }

    private AuthenticationContext getAuthenticationContextForPayloadTest(String payloadType)
            throws JsTestException {

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource(ANALYTICS_PAYLOAD_TEST_SP, this);
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                sp1.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig authenticationScriptConfig = localAndOutboundAuthenticationConfig
                .getAuthenticationScriptConfig();

        String jsonPayload = sequenceHandlerRunner.loadJson(ANALYTICS_PAYLOAD, this).toString();
        String content = authenticationScriptConfig.getContent();
        String newContent =
                String.format(content, jsonPayload, jsonPayload, ANALYTICS_SERVICE_CHECK_PAYLOAD, payloadType);
        authenticationScriptConfig.setContent(newContent);
        localAndOutboundAuthenticationConfig.setAuthenticationScriptConfig(authenticationScriptConfig);
        sp1.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();
        return context;
    }

    @POST
    @Path("/{appName}/{inputStream}")
    @Consumes("application/json")
    @Produces("application/json")
    public Map<String, Map<String, String>> analyticsReceiver(@PathParam("appName") String appName,
                                                              @PathParam("inputStream") String inputStream,
                                                              Map<String, Map<String, String>> data) {

        Map<String, String> event = data.get("event");
        String username = event.get("username");
        Map<String, String> responseEvent = new HashMap<>();
        responseEvent.put("username", username);
        responseEvent.put("riskScore", "1");
        Map<String, Map<String, String>> response = new HashMap<>();
        response.put("event", responseEvent);
        return response;
    }

    @POST
    @Path(ANALYTICS_SERVICE_CHECK_PAYLOAD)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> analyticsReceiverCheckPayload(Map<String, Object> data) throws JsTestException {

        JsonObject expectedPayload = sequenceHandlerRunner.loadJson(ANALYTICS_PAYLOAD_JSON, this);
        Gson gson = new Gson();
        String dataStr = gson.toJson(data.get("event"));
        JsonObject actualPayload = gson.fromJson(dataStr, JsonObject.class);

        if (expectedPayload.equals(actualPayload)) {
            Map<String, String> responseEvent = new HashMap<>();
            responseEvent.put("riskScore", "1");
            Map<String, Object> response = new HashMap<>();
            response.put("event", responseEvent);
            response.put("payload", actualPayload);
            return response;
        } else {
            throw new JsTestException("Payloads do not match. " +
                    String.format("Expected payload: %s, Actual payload: %s", expectedPayload, actualPayload));
        }
    }

    /**
     * Response validator implementation.
     */
    public class ResponseValidatorImpl implements ResponseValidator {

        /**
         * Validate the response.
         *
         * @param response JSON Response from the analytics engine.
         * @return True if the response matches the expected JSON response.
         */
        @Override
        @HostAccess.Export
        public boolean validateResponse(JsParameters response) throws JsTestException {

            if (response != null) {
                JsonObject expectedResponse = sequenceHandlerRunner.loadJson(ANALYTICS_PAYLOAD_JSON, this);
                Gson gson = new Gson();
                String dataStr = gson.toJson(response.getWrapped());
                JsonObject actualResponse = gson.fromJson(dataStr, JsonObject.class);
                return actualResponse.equals(expectedResponse);
            }
            return false;
        }
    }
}

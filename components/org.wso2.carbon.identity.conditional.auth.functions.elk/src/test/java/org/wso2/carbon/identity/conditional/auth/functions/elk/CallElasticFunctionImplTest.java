/*
 *  Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.elk;


import com.google.gson.Gson;
import org.json.JSONObject;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.CacheBackedLongWaitStatusDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.LongWaitStatusDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.store.LongWaitStatusStoreService;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithMicroService;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.common.testng.InjectMicroservicePort;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.msf4j.Response;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2_http.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class CallElasticFunctionImplTest extends JsSequenceHandlerAbstractTest {

    private static final String TEST_SP_CONFIG = "elk-test-sp.xml";
    private static final String ELASTIC_PAYLOAD_TEMPLATE = "{\"risk_score\":{\"value\":%d}}";
    private static final String LOCALHOST = "http://localhost:";
    private static final Gson gsonInstance = new Gson();

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeClass
    @Parameters({"scriptEngine"})
    protected void initClass(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("callElastic", new CallElasticFunctionImpl());
    }

    @Test
    public void testRiskScore() throws JsTestException, NoSuchFieldException,
            IllegalAccessException,
            IdentityGovernanceException {

        IdentityGovernanceService identityGovernanceService = Mockito.mock(IdentityGovernanceService.class);
        FunctionsDataHolder functionsDataHolder = Mockito.mock(FunctionsDataHolder.class);
        Mockito.when(functionsDataHolder.getIdentityGovernanceService()).thenReturn(identityGovernanceService);
        Property property = new Property();
        property.setValue(LOCALHOST + microServicePort + "/");
        Mockito.when(identityGovernanceService.getConfiguration(new String[]{ElasticAnalyticsEngineConfigImpl.RECEIVER},
                "test_domain")).thenReturn(new Property[]{property});

        Field functionsDataHolderInstance = FunctionsDataHolder.class.getDeclaredField("instance");
        functionsDataHolderInstance.setAccessible(true);
        functionsDataHolderInstance.set(null, functionsDataHolder);

        Field frameworkServiceDataHolderInstance = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolderInstance.setAccessible(true);
        FrameworkServiceDataHolder availableInstance = (FrameworkServiceDataHolder) frameworkServiceDataHolderInstance.get(null);

        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        availableInstance.setLongWaitStatusStoreService(longWaitStatusStoreService);

        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(TEST_SP_CONFIG, this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);

        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        assertNotNull(context.getSelectedAcr());
        assertEquals(context.getSelectedAcr(), "2", "Expected acr value not found");
    }

    @POST
    @Path("/transaction/_search")
    @Consumes("application/json")
    public String dummyPost(Map<String, Object> data, @Context Response res) {

        Map<String, Object> response = new HashMap<>();

        String jsonQuery = gsonInstance.toJson(data.get("query"));
        JSONObject query = new JSONObject(jsonQuery);

        String username = query
                .getJSONObject("bool")
                .getJSONArray("must")
                .getJSONObject(0)
                .getJSONObject("match")
                .getString("username.keyword");

        Object aggregations;
        if (username.equals("admin")) {
            aggregations = gsonInstance.fromJson(String.format(ELASTIC_PAYLOAD_TEMPLATE, 2), Object.class);
        } else {
            aggregations = gsonInstance.fromJson(String.format(ELASTIC_PAYLOAD_TEMPLATE, 0), Object.class);
        }

        response.put("aggregations", aggregations);

        return gsonInstance.toJson(response);
    }
}

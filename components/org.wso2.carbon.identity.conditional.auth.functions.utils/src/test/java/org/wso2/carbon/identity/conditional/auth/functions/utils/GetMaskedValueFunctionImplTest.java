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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.testng.annotations.DataProvider;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;

import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Test class for GetMaskedValueFunctionImplTest.
 */
@WithCarbonHome
@WithH2Database(files = "dbscripts/h2.sql")
@WithRealmService(injectToSingletons = {LoggerUtils.class, FrameworkServiceDataHolder.class})
public class GetMaskedValueFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @BeforeClass
    @Parameters({"scriptEngine"})
    public void setUp(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("getMaskedValue",
                new GetMaskedValueFunctionImpl());
    }

    @Test(dataProvider = "maskableValueProvider")
    public void testGetMaskedValue(boolean isLogMaskingEnabled, String username, String expectedMaskedValue)
            throws JsTestException {

        LoggerUtils.isLogMaskingEnable = isLogMaskingEnabled;
        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator", username, Collections.emptyMap());

        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource("get-masked-value-sp.xml", this);
        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "test_domain");

        Assert.assertEquals(context.getSelectedAcr(), expectedMaskedValue);
    }

    @DataProvider(name = "maskableValueProvider")
    public Object[][] maskableValueProvider() {

        /*
        The "getMaskedValue" method should always mask the passed in value
        irrespective of the server-wide 'isLogMaskingEnable' configuration.
         */
        return new Object[][]{
                {true, "johndoe", "j*****e"},
                {false, "johndoe", "j*****e"},
        };
    }
}

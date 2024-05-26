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
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.script.AuthenticationScriptConfig;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.core.common.User;

import java.lang.reflect.Field;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@WithCarbonHome
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@WithH2Database(files = "dbscripts/h2.sql")
public class ResolveMultiAttributeLoginIdentifierFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @Mock
    private MultiAttributeLoginService multiAttributeLoginServiceMock;

    @BeforeClass
    @Parameters({"scriptEngine"})
    public void setUp(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("resolveMultiAttributeLoginIdentifier",
                new ResolveMultiAttributeLoginIdentifierFunctionImpl());

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
                                                         String loginIdentifier, String username)
            throws JsTestException {

        ResolvedUserResult userResult = new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.SUCCESS);
        if (multiAttributeLoginEnabled) {
            User user = new User("123456", username, username);
            userResult.setUser(user);
        } else {
            userResult.setResolvedStatus(ResolvedUserResult.UserResolvedStatus.FAIL);
        }

        when(multiAttributeLoginServiceMock.isEnabled(anyString())).thenReturn(multiAttributeLoginEnabled);
        when(multiAttributeLoginServiceMock.resolveUser(loginIdentifier, "test_domain")).thenReturn(userResult);

        AuthenticationContext context = getAuthenticationContextForSP(loginIdentifier);
        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "test_domain");

        String returnResult = context.getSelectedAcr();
        Assert.assertNotNull(returnResult);
        if (multiAttributeLoginEnabled) {
            Assert.assertEquals(returnResult, username);
        } else {
            Assert.assertEquals(returnResult, "NONE");
        }
    }

    private AuthenticationContext getAuthenticationContextForSP(String loginIdentifier) throws JsTestException {

        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator", "test_user", Collections.emptyMap());
        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(
                "resolve-multi-attribute-login-sp.xml", this);

        LocalAndOutboundAuthenticationConfig authConfig = sp.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig scriptConfig = authConfig.getAuthenticationScriptConfig();
        String content = scriptConfig.getContent();
        String newContent = String.format(content, loginIdentifier);
        scriptConfig.setContent(newContent);
        authConfig.setAuthenticationScriptConfig(scriptConfig);
        sp.setLocalAndOutBoundAuthenticationConfig(authConfig);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        return context;
    }
}

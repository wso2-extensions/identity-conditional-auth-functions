/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.common.utils;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.lang.reflect.Constructor;

import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for {@link ConfigProvider}.
 */
@WithCarbonHome
public class ConfigProviderTest {

    /**
     * Create a fresh {@link ConfigProvider} instance through its private constructor so that the
     * configuration is read while the mocked {@link IdentityUtil} is in scope, independent of the
     * class-loaded singleton.
     *
     * @return A new ConfigProvider instance.
     * @throws Exception If the reflective instantiation fails.
     */
    private ConfigProvider newConfigProvider() throws Exception {

        Constructor<ConfigProvider> constructor = ConfigProvider.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        return constructor.newInstance();
    }

    /**
     * Data provider for {@link #testHttpFunctionsConnectionPoolConfig}.
     *
     * Columns: maxConnections, maxConnectionsPerRoute, expectedMaxConnections, expectedMaxConnectionsPerRoute
     */
    @DataProvider(name = "httpFunctionsConnectionPoolDataProvider")
    public Object[][] httpFunctionsConnectionPoolDataProvider() {

        return new Object[][]{
                // Valid values are parsed and used.
                {"50", "30", 50, 30},
                // Properties not configured (null) fall back to the default of 20.
                {null, null, 20, 20},
                // Invalid (non-numeric) values fall back to the default of 20.
                {"invalid", "not-a-number", 20, 20},
        };
    }

    @Test(dataProvider = "httpFunctionsConnectionPoolDataProvider")
    public void testHttpFunctionsConnectionPoolConfig(String maxConnections, String maxConnectionsPerRoute,
            int expectedMaxConnections, int expectedMaxConnectionsPerRoute) throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(
                    Constants.HTTP_FUNCTIONS_MAX_CONNECTIONS)).thenReturn(maxConnections);
            identityUtil.when(() -> IdentityUtil.getProperty(
                    Constants.HTTP_FUNCTIONS_MAX_CONNECTIONS_PER_ROUTE)).thenReturn(maxConnectionsPerRoute);

            ConfigProvider configProvider = newConfigProvider();

            Assert.assertEquals(configProvider.getHttpFunctionsMaxConnections(), expectedMaxConnections);
            Assert.assertEquals(configProvider.getHttpFunctionsMaxConnectionsPerRoute(),
                    expectedMaxConnectionsPerRoute);
        }
    }
}

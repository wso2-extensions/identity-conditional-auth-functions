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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.http.internal;

import org.mockito.ArgumentCaptor;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.conditional.auth.functions.http.AbstractHTTPFunction;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.TenantHttpClientManager;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Verifies that the HTTP functions release their per-tenant clients when the component is deactivated.
 */
@WithCarbonHome
public class HTTPFunctionsServiceComponentTest {

    @Test
    public void testDeactivateClosesHttpFunctions() throws Exception {

        JsFunctionRegistry registry = mock(JsFunctionRegistry.class);
        HTTPFunctionsServiceHolder.getInstance().setJsFunctionRegistry(registry);
        HTTPFunctionsServiceComponent component = new HTTPFunctionsServiceComponent();

        component.activate(null);
        ArgumentCaptor<Object> functions = ArgumentCaptor.forClass(Object.class);
        verify(registry, times(4)).register(eq(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER), any(String.class),
                functions.capture());
        List<TenantHttpClientManager> managers = new ArrayList<>();
        for (Object function : functions.getAllValues()) {
            if (function instanceof AbstractHTTPFunction) {
                managers.add(getManager((AbstractHTTPFunction) function));
            }
        }
        assertEquals(managers.size(), 2, "httpGet and httpPost should both be registered.");
        for (TenantHttpClientManager manager : managers) {
            assertFalse(manager.isClosed());
        }

        component.deactivate(null);

        for (TenantHttpClientManager manager : managers) {
            assertTrue(manager.isClosed(), "Tenant clients should be closed on deactivate.");
        }
        for (String fieldName : new String[]{"httpPostFunction", "httpGetFunction"}) {
            Field field = HTTPFunctionsServiceComponent.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            assertNull(field.get(component), fieldName + " should be released.");
        }
        HTTPFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    private TenantHttpClientManager getManager(AbstractHTTPFunction function) throws Exception {

        Field field = AbstractHTTPFunction.class.getDeclaredField("tenantClients");
        field.setAccessible(true);
        return (TenantHttpClientManager) field.get(function);
    }
}

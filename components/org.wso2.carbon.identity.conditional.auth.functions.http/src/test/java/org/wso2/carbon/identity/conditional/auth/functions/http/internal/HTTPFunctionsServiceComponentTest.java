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

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.conditional.auth.functions.http.AbstractHTTPFunction;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.expectThrows;

/**
 * Verifies that the HTTP functions release their HTTP clients when the component is deactivated.
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
        List<CloseableHttpClient> clients = new ArrayList<>();
        for (Object function : functions.getAllValues()) {
            if (function instanceof AbstractHTTPFunction) {
                clients.add(getClient((AbstractHTTPFunction) function));
            }
        }
        assertEquals(clients.size(), 2, "httpGet and httpPost should both be registered.");

        component.deactivate(null);

        for (CloseableHttpClient client : clients) {
            // A closed client has shut down its connection pool and rejects any further request.
            expectThrows(IllegalStateException.class, () -> client.execute(new HttpGet("http://localhost:1")));
        }
        for (String fieldName : new String[]{"httpPostFunction", "httpGetFunction"}) {
            Field field = HTTPFunctionsServiceComponent.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            assertNull(field.get(component), fieldName + " should be released.");
        }
        HTTPFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    private CloseableHttpClient getClient(AbstractHTTPFunction function) throws Exception {

        Field field = AbstractHTTPFunction.class.getDeclaredField("client");
        field.setAccessible(true);
        return (CloseableHttpClient) field.get(function);
    }
}

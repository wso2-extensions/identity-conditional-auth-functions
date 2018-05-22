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
 *
 */

package org.wso2.carbon.identity.conditional.auth.functions.http.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.conditional.auth.functions.http.CallHTTPFunction;
import org.wso2.carbon.identity.conditional.auth.functions.http.CallHTTPFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.http.CookieFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.http.GetCookieFunction;
import org.wso2.carbon.identity.conditional.auth.functions.http.SetCookieFunction;

/**
 * OSGi declarative services component which handle cookie related conditional auth functions.
 */

@Component(
        name = "identity.conditional.auth.functions.cookie.component",
        immediate = true
)
public class CookieFunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(CookieFunctionsServiceComponent.class);

    public static final String FUNC_CALL_HTTP = "callHTTP";
    public static final String FUNC_SET_COOKIE = "setCookie";
    public static final String FUNC_GET_COOKIE_VALUE = "getCookieValue";

    @Activate
    protected void activate(ComponentContext ctxt) {

        CookieFunctionImpl cookieFunction = new CookieFunctionImpl();
        JsFunctionRegistry jsFunctionRegistry = CookieFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "setCookie",
                (SetCookieFunction) cookieFunction::setCookie);
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getCookieValue",
                (GetCookieFunction) cookieFunction::getCookieValue);

        CallHTTPFunction callHTTP = new CallHTTPFunctionImpl();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_HTTP,
                callHTTP);
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = CookieFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_SET_COOKIE);
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_GET_COOKIE_VALUE);
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_HTTP);
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        CookieFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        CookieFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }
}

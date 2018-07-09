/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.identity.conditional.auth.functions.session.internal;

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
import org.wso2.carbon.identity.conditional.auth.functions.session.function.ExecuteActionFunction;
import org.wso2.carbon.identity.conditional.auth.functions.session.function.GetSessionDataFunction;
import org.wso2.carbon.identity.conditional.auth.functions.session.function.GetUserSessionDataFunction;
import org.wso2.carbon.identity.conditional.auth.functions.session.function.IsWithinSessionLimitFunction;
import org.wso2.carbon.identity.conditional.auth.functions.session.function.KillSessionFunction;
import org.wso2.carbon.identity.conditional.auth.functions.session.function.IsValid;

@Component(
        name = "session.based.conditional.authentication.function.component",
        immediate = true
)
public class SessionBasedJSFunctionsComponent {

    private static Log log = LogFactory.getLog(SessionBasedJSFunctionsComponent.class);

    private JsFunctionRegistry jsFunctionRegistry;
    private IsWithinSessionLimitFunction isWithinSessionLimitFunction;
    private KillSessionFunction killSessionFunction;
    private GetSessionDataFunction getSessionDataFunction;

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            isWithinSessionLimitFunction = new IsWithinSessionLimitFunction();
            killSessionFunction = new KillSessionFunction();
            getSessionDataFunction = new GetSessionDataFunction();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "isWithinSessionLimit",
                    (IsValid) isWithinSessionLimitFunction::validate);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "killSession",
                    (ExecuteActionFunction) killSessionFunction::execute);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getSessionData",
                    (GetUserSessionDataFunction) getSessionDataFunction::getData);
            if (log.isDebugEnabled()) {
                log.info("Session based conditional authentication component bundle activated");
            }
        } catch (Throwable e) {
            log.error("Session based conditional authentication component bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                    "isWithinSessionLimit");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                    "killSession");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                    "getSessionData");
        }
        if (log.isDebugEnabled()) {
            log.info("SessionCountAuthenticator bundle is deactivated");
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        this.jsFunctionRegistry = jsFunctionRegistry;
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        this.jsFunctionRegistry = null;
    }

}

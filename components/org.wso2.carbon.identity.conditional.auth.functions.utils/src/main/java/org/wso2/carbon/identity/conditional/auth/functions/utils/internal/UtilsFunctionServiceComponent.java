/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.utils.internal;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.conditional.auth.functions.utils.FilterAuthenticatorsFunction;
import org.wso2.carbon.identity.conditional.auth.functions.utils.FilterAuthenticatorsFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.utils.GetMaskedValueFunction;
import org.wso2.carbon.identity.conditional.auth.functions.utils.GetMaskedValueFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.utils.ResolveMultiAttributeLoginIdentifierFunction;
import org.wso2.carbon.identity.conditional.auth.functions.utils.ResolveMultiAttributeLoginIdentifierFunctionImpl;

/**
 * OSGi declarative services component which handles registration and de-registration of utils related
 * conditional auth functions.
 */
@Component(
        name = "identity.conditional.auth.functions.utils.component",
        immediate = true
)
public class UtilsFunctionServiceComponent {

    @Activate
    protected void activate(ComponentContext ctxt) {

        FilterAuthenticatorsFunction filterAuthenticatorsFunctionImpl = new FilterAuthenticatorsFunctionImpl();
        JsFunctionRegistry jsFunctionRegistry = UtilsFunctionServiceHolder.getInstance().getJsFunctionRegistry();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "filterAuthenticators",
                filterAuthenticatorsFunctionImpl);

        ResolveMultiAttributeLoginIdentifierFunction resolveMultiAttributeLoginIdentifierFunctionImpl =
                new ResolveMultiAttributeLoginIdentifierFunctionImpl();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                "resolveMultiAttributeLoginIdentifier", resolveMultiAttributeLoginIdentifierFunctionImpl);

        GetMaskedValueFunction getMaskedValueFunctionImpl = new GetMaskedValueFunctionImpl();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getMaskedValue",
                getMaskedValueFunctionImpl);
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = UtilsFunctionServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "filterAuthenticators");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                    "resolveMultiAttributeLoginIdentifier");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getMaskedValue");
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        UtilsFunctionServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        UtilsFunctionServiceHolder.getInstance().setJsFunctionRegistry(null);
    }
}

/*
 * Copyright (c) 2018-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.notification;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.conditional.auth.functions.notification.internal.NotificationFunctionServiceHolder;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.event.handler.notification.exception.NotificationRuntimeException;

import java.util.HashMap;
import java.util.Map;

/**
 * Contains the sendEmail() function implementation.
 */
public class SendEmailFunctionImpl implements SendEmailFunction {

    private static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";

    private static final Log LOG = LogFactory.getLog(SendEmailFunctionImpl.class);

    @Override
    @HostAccess.Export
    public boolean sendMail(JsAuthenticatedUser user, String templateId, Map<String, String> paramMap) {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>(paramMap);
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getWrapped().getUserName());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getWrapped().getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getWrapped().getUserStoreDomain());
        properties.put(TEMPLATE_TYPE, templateId);

        if (user.getWrapped().isFederatedUser()) {
            properties.put(NotificationConstants.IS_FEDERATED_USER, user.getWrapped().isFederatedUser());
            properties.put(NotificationConstants.FEDERATED_USER_CLAIMS, user.getWrapped().getUserAttributes());
        }

        Event identityMgtEvent = new Event(eventName, properties);
        try {
            NotificationFunctionServiceHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException | NotificationRuntimeException e) {
            LOG.error(String.format("Error when sending notification of template %s to user %s", templateId, user
                    .getWrapped().toFullQualifiedUsername()), e);
            return false;
        }
        return true;
    }
}

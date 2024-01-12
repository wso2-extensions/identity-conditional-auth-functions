/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.notification;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticatedUser;

import java.util.Map;

@FunctionalInterface
public interface SendEmailFunction {

    /**
     * Send an email to the given user using a provided template.
     * @param user The user object to whom the mail is send
     * @param templateId The email template id, Which is configured under email templates.
     * @param paramMap Placeholder value map
     * @return <code>true</code> if the email is successfully queued to be sent. <code>false</code> If the mail
     * couldn't be queued due to any error.
     */
    boolean sendMail(JsBaseAuthenticatedUser user, String templateId, Map<String, String> paramMap);

}

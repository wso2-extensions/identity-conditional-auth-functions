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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.user.model.utils;

import java.util.Map;

/**
 * This class represents required parameters to update user's password.
 */
public class UserPasswordUpdateModel {

    private final char[] newPassword;
    private final Map<String,Object> eventHandlers;
    private final boolean skipPasswordValidation;

    private UserPasswordUpdateModel(UserPasswordUpdateModelBuilder builder) {

        this.newPassword           = builder.newPassword;
        this.eventHandlers         = builder.eventHandlers;
        this.skipPasswordValidation= builder.skipPasswordValidation;
    }

    public char[] getNewPassword() {

        return newPassword.clone();
    }

    public Map<String,Object> getEventHandlers() {

        return eventHandlers;
    }

    public boolean isSkipPasswordValidation() {

        return skipPasswordValidation;
    }

    /**
     * Builder class for {@link UserPasswordUpdateModel}
     */
    public static class UserPasswordUpdateModelBuilder {

        private final char[] newPassword;
        private Map<String,Object> eventHandlers;
        private boolean skipPasswordValidation;

        public UserPasswordUpdateModelBuilder(char[] newPassword) {

            this.newPassword = newPassword;
        }

        public UserPasswordUpdateModelBuilder eventHandlers(Map<String,Object> handlers) {

            this.eventHandlers = handlers;
            return this;
        }
        public UserPasswordUpdateModelBuilder skipPasswordValidation(boolean skip) {

            this.skipPasswordValidation = skip;
            return this;
        }

        public UserPasswordUpdateModel build() {

            return new UserPasswordUpdateModel(this);
        }
    }
}

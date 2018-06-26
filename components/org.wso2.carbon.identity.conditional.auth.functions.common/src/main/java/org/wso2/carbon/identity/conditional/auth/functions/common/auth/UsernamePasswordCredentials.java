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
 */

package org.wso2.carbon.identity.conditional.auth.functions.common.auth;

import org.apache.http.util.LangUtils;

import java.security.Principal;

/**
 * Username password credential implementation.
 */
public class UsernamePasswordCredentials implements Credentials {
    private final BasicUserPrincipal principal;
    private final String password;

    public UsernamePasswordCredentials(String userName, String password) {

        this.principal = new BasicUserPrincipal(userName);
        this.password = password;
    }

    public Principal getUserPrincipal() {
        return this.principal;
    }

    public String getUserName() {
        return this.principal.getName();
    }

    public String getPassword() {
        return this.password;
    }

    public int hashCode() {
        return this.principal.hashCode();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else {
            if (o instanceof UsernamePasswordCredentials) {
                UsernamePasswordCredentials that = (UsernamePasswordCredentials)o;
                return LangUtils.equals(this.principal, that.principal);
            }

            return false;
        }
    }

    public String toString() {
        return this.principal.toString();
    }
}

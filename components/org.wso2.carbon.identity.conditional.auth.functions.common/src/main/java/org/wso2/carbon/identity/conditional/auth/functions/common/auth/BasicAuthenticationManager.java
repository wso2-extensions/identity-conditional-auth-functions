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

import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AUTH;
import org.apache.http.message.BufferedHeader;
import org.apache.http.util.CharArrayBuffer;

import java.util.Base64;

/**
 * Basic authentication manager.
 */
public class BasicAuthenticationManager implements AuthenticationManager {

    @Override
    public Header authenticate(
            final Credentials credentials,
            final HttpRequest request) {

        final StringBuilder tmp = new StringBuilder();
        tmp.append(credentials.getUserPrincipal().getName());
        tmp.append(":");
        tmp.append((credentials.getPassword() == null) ? "" : credentials.getPassword());

        final byte[] base64password = Base64.getEncoder().encode(tmp.toString().getBytes());

        final CharArrayBuffer buffer = new CharArrayBuffer(32);

        //TODO handle proxy
        buffer.append(AUTH.WWW_AUTH_RESP);

        buffer.append(": Basic ");
        buffer.append(base64password, 0, base64password.length);

        return new BufferedHeader(buffer);
    }
}

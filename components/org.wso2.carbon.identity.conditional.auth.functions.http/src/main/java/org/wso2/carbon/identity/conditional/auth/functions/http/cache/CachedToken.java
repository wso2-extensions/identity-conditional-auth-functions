/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
package org.wso2.carbon.identity.conditional.auth.functions.http.cache;

import java.io.Serializable;
import java.time.Instant;

/**
 * Immutable cache entry that pairs an access token string with its expiry time expressed as
 * Unix epoch seconds. Storing both values in a single object ensures the token and its expiry
 * are written to (and evicted from) the cache atomically.
 * <p>
 * Instances are only created when a valid expiry can be determined — either from the JWT
 * {@code exp} claim or from the {@code expires_in} response parameter. Tokens whose expiry
 * cannot be resolved are never wrapped in a {@code CachedToken} and are therefore not cached.
 */
public class CachedToken implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String accessToken;
    private final long expiryEpoch;

    /**
     * @param accessToken The raw access token string
     * @param expiryEpoch Token expiry as Unix epoch seconds (must be a future instant)
     */
    public CachedToken(String accessToken, long expiryEpoch) {

        this.accessToken = accessToken;
        this.expiryEpoch = expiryEpoch;
    }

    /**
     * @return The raw access token string
     */
    public String getAccessToken() {

        return accessToken;
    }

    /**
     * @return Token expiry as Unix epoch seconds
     */
    public long getExpiryEpoch() {

        return expiryEpoch;
    }

    /**
     * Returns {@code true} if the current time is at or past the token's expiry epoch.
     *
     * @return {@code true} if the token has expired
     */
    public boolean isExpired() {

        return Instant.now().getEpochSecond() >= expiryEpoch;
    }
}

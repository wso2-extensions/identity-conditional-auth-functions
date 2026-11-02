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

package org.wso2.carbon.identity.conditional.auth.functions.http.util;

import org.apache.http.client.CookieStore;
import org.apache.http.impl.client.BasicCookieStore;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * Keeps one {@link CookieStore} per tenant domain, so that cookies set by an endpoint called from one tenant's
 * adaptive script are never sent on requests made for another tenant.
 * <p>
 * Lookups are lock free. The number of stores is capped (the least recently used tenants are dropped first) and
 * stores idle for longer than the idle timeout are dropped. Cleanup runs on the calling thread at most once per
 * cleanup interval, or straight away when the cap is exceeded, and never blocks other callers. Dropping a store only
 * forgets that tenant's cookies, as if they had expired.
 */
public class TenantCookieStores {

    private static final String DEFAULT_TENANT_KEY = "carbon.super";

    private final ConcurrentHashMap<String, Entry> stores = new ConcurrentHashMap<>();
    private final int maxTenants;
    private final long idleTimeoutMillis;
    private final long cleanupIntervalMillis;
    private final LongSupplier clock;
    private final ReentrantLock cleanupLock = new ReentrantLock();
    private volatile long nextCleanup;

    public TenantCookieStores(int maxTenants, long idleTimeoutMillis) {

        this(maxTenants, idleTimeoutMillis, System::currentTimeMillis);
    }

    /**
     * Constructor with an explicit clock (epoch milliseconds), mainly for tests.
     */
    public TenantCookieStores(int maxTenants, long idleTimeoutMillis, LongSupplier clock) {

        if (maxTenants < 1) {
            throw new IllegalArgumentException("Maximum number of tenant cookie stores must be at least 1.");
        }
        this.maxTenants = maxTenants;
        this.idleTimeoutMillis = idleTimeoutMillis;
        // Sweep for idle tenants a few times per idle timeout, not on every request.
        this.cleanupIntervalMillis = Math.max(1, idleTimeoutMillis / 4);
        this.clock = clock;
        this.nextCleanup = clock.getAsLong() + cleanupIntervalMillis;
    }

    /**
     * Get the cookie store of the tenant, creating it if needed.
     *
     * @param tenantDomain Tenant domain. Null or blank falls back to the super tenant.
     * @return Cookie store of the tenant.
     */
    public CookieStore get(String tenantDomain) {

        String key = tenantDomain == null || tenantDomain.trim().isEmpty() ? DEFAULT_TENANT_KEY : tenantDomain;
        long now = clock.getAsLong();
        Entry entry = stores.computeIfAbsent(key, k -> new Entry());
        entry.lastUsed = now;
        if (now >= nextCleanup || stores.size() > maxTenants) {
            cleanUp(now);
        }
        return entry.store;
    }

    /**
     * Number of tenants that currently hold a cookie store.
     *
     * @return Number of cookie stores.
     */
    public int size() {

        return stores.size();
    }

    /**
     * Drop the cookies of all tenants.
     */
    public void clear() {

        stores.clear();
    }

    private void cleanUp(long now) {

        // Another thread is already cleaning up; no need to wait for it.
        if (!cleanupLock.tryLock()) {
            return;
        }
        try {
            nextCleanup = now + cleanupIntervalMillis;
            if (idleTimeoutMillis > 0) {
                stores.entrySet().removeIf(e -> now - e.getValue().lastUsed > idleTimeoutMillis);
            }
            int excess = stores.size() - maxTenants;
            if (excess > 0) {
                // Snapshot the access times, since other threads keep updating them while we sort.
                List<Candidate> byAge = new ArrayList<>();
                for (Map.Entry<String, Entry> e : stores.entrySet()) {
                    byAge.add(new Candidate(e.getKey(), e.getValue()));
                }
                byAge.sort(Comparator.comparingLong(c -> c.lastUsed));
                for (int i = 0; i < excess && i < byAge.size(); i++) {
                    stores.remove(byAge.get(i).key, byAge.get(i).entry);
                }
            }
        } finally {
            cleanupLock.unlock();
        }
    }

    private static final class Entry {

        // BasicCookieStore is thread safe, so concurrent requests of the same tenant can share it.
        private final CookieStore store = new BasicCookieStore();
        private volatile long lastUsed;
    }

    private static final class Candidate {

        private final String key;
        private final Entry entry;
        private final long lastUsed;

        private Candidate(String key, Entry entry) {

            this.key = key;
            this.entry = entry;
            this.lastUsed = entry.lastUsed;
        }
    }
}

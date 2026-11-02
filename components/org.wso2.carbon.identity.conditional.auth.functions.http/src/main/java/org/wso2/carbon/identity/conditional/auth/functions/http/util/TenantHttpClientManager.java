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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.impl.client.CloseableHttpClient;

import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Holds one {@link CloseableHttpClient} (and hence one connection pool) per tenant domain so that a slow endpoint
 * of one tenant cannot exhaust the connections available to other tenants.
 * <p>
 * Clients are created lazily. The number of live clients is capped (least recently used tenants are evicted first)
 * and clients that have been idle for longer than the idle timeout are evicted lazily on the next acquire. An evicted
 * client is closed straight away unless requests are still running on it, in which case it is closed when the last
 * of those requests releases its lease.
 */
public class TenantHttpClientManager implements Closeable {

    private static final Log LOG = LogFactory.getLog(TenantHttpClientManager.class);
    private static final String DEFAULT_TENANT_KEY = "carbon.super";

    private final Supplier<CloseableHttpClient> clientFactory;
    private final int maxClients;
    private final long idleTimeoutMillis;
    private final Supplier<Long> clock;
    // Access ordered, so the eldest entry is the least recently used tenant.
    private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>(16, 0.75f, true);
    private boolean closed;

    public TenantHttpClientManager(Supplier<CloseableHttpClient> clientFactory, int maxClients,
                                   long idleTimeoutMillis) {

        this(clientFactory, maxClients, idleTimeoutMillis, System::currentTimeMillis);
    }

    /**
     * Constructor with an explicit clock (epoch milliseconds), mainly for tests.
     */
    public TenantHttpClientManager(Supplier<CloseableHttpClient> clientFactory, int maxClients,
                                   long idleTimeoutMillis, Supplier<Long> clock) {

        if (maxClients < 1) {
            throw new IllegalArgumentException("Maximum number of tenant clients must be at least 1.");
        }
        this.clientFactory = clientFactory;
        this.maxClients = maxClients;
        this.idleTimeoutMillis = idleTimeoutMillis;
        this.clock = clock;
    }

    /**
     * Get the client of the tenant, creating it if needed. The caller must close the returned lease once the request
     * has completed.
     *
     * @param tenantDomain Tenant domain. Null or blank falls back to the super tenant.
     * @return Lease on the tenant's client.
     */
    public synchronized Lease acquire(String tenantDomain) {

        if (closed) {
            throw new IllegalStateException("The HTTP client manager has been closed.");
        }
        String key = tenantDomain == null || tenantDomain.trim().isEmpty() ? DEFAULT_TENANT_KEY : tenantDomain;
        long now = clock.get();
        evictIdle(now);
        Entry entry = entries.get(key);
        if (entry == null) {
            entry = new Entry(clientFactory.get());
            entries.put(key, entry);
            evictOverflow(key);
        }
        entry.lastUsed = now;
        entry.inFlight++;
        return new Lease(entry);
    }

    /**
     * Number of tenants that currently have a live client in the cache.
     *
     * @return Cached client count.
     */
    public synchronized int size() {

        return entries.size();
    }

    public synchronized boolean isClosed() {

        return closed;
    }

    /**
     * Close every client. Clients with running requests are closed when those requests finish.
     */
    @Override
    public synchronized void close() {

        closed = true;
        for (Entry entry : entries.values()) {
            retire(entry);
        }
        entries.clear();
    }

    private void evictIdle(long now) {

        if (idleTimeoutMillis <= 0) {
            return;
        }
        Iterator<Entry> iterator = entries.values().iterator();
        while (iterator.hasNext()) {
            Entry entry = iterator.next();
            // A tenant with running requests is by definition not idle.
            if (entry.inFlight == 0 && now - entry.lastUsed > idleTimeoutMillis) {
                iterator.remove();
                retire(entry);
            }
        }
    }

    private void evictOverflow(String keepKey) {

        Iterator<Map.Entry<String, Entry>> iterator = entries.entrySet().iterator();
        while (entries.size() > maxClients && iterator.hasNext()) {
            Map.Entry<String, Entry> eldest = iterator.next();
            if (eldest.getKey().equals(keepKey)) {
                continue;
            }
            iterator.remove();
            retire(eldest.getValue());
        }
    }

    private void retire(Entry entry) {

        entry.retired = true;
        if (entry.inFlight == 0) {
            closeQuietly(entry);
        }
    }

    private synchronized void release(Entry entry) {

        entry.inFlight--;
        entry.lastUsed = clock.get();
        if (entry.retired && entry.inFlight == 0) {
            closeQuietly(entry);
        }
    }

    private void closeQuietly(Entry entry) {

        try {
            entry.client.close();
        } catch (IOException e) {
            LOG.warn("Error while closing a tenant HTTP client.", e);
        }
    }

    private static final class Entry {

        private final CloseableHttpClient client;
        private long lastUsed;
        private int inFlight;
        private boolean retired;

        private Entry(CloseableHttpClient client) {

            this.client = client;
        }
    }

    /**
     * Lease on a tenant's client. Closing it lets the manager close the client if it was evicted meanwhile.
     */
    public final class Lease implements AutoCloseable {

        private final Entry entry;
        private boolean released;

        private Lease(Entry entry) {

            this.entry = entry;
        }

        public CloseableHttpClient getClient() {

            return entry.client;
        }

        @Override
        public void close() {

            synchronized (TenantHttpClientManager.this) {
                if (released) {
                    return;
                }
                released = true;
                release(entry);
            }
        }
    }
}

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

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.apache.http.impl.client.CloseableHttpClient;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.TenantHttpClientManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.expectThrows;

/**
 * Tests the per-tenant client selection, eviction and close behaviour.
 */
public class TenantHttpClientManagerTest {

    private static final long IDLE_TIMEOUT = 1000;

    private List<CloseableHttpClient> created;
    private AtomicLong now;

    @BeforeMethod
    public void setUp() {

        created = new ArrayList<>();
        now = new AtomicLong(0);
    }

    private TenantHttpClientManager newManager(int maxClients) {

        return new TenantHttpClientManager(() -> {
            CloseableHttpClient client = mock(CloseableHttpClient.class);
            created.add(client);
            return client;
        }, maxClients, IDLE_TIMEOUT, now::get);
    }

    private CloseableHttpClient clientOf(TenantHttpClientManager manager, String tenant) {

        try (TenantHttpClientManager.Lease lease = manager.acquire(tenant)) {
            return lease.getClient();
        }
    }

    @Test
    public void testSameTenantSharesClientAndTenantsAreIsolated() {

        TenantHttpClientManager manager = newManager(10);
        CloseableHttpClient a1 = clientOf(manager, "a.com");
        CloseableHttpClient a2 = clientOf(manager, "a.com");
        CloseableHttpClient b = clientOf(manager, "b.com");

        assertSame(a1, a2);
        assertNotSame(a1, b);
        assertEquals(created.size(), 2);
    }

    @Test
    public void testNullAndBlankTenantFallBackToSuperTenant() {

        TenantHttpClientManager manager = newManager(10);
        CloseableHttpClient viaNull = clientOf(manager, null);
        assertSame(clientOf(manager, " "), viaNull);
        assertSame(clientOf(manager, "carbon.super"), viaNull);
        assertEquals(manager.size(), 1);
    }

    @Test
    public void testLeastRecentlyUsedTenantEvictedAndClosedWhenCapExceeded() throws IOException {

        TenantHttpClientManager manager = newManager(2);
        CloseableHttpClient a = clientOf(manager, "a.com");
        CloseableHttpClient b = clientOf(manager, "b.com");
        clientOf(manager, "a.com"); // a is now more recent than b.
        clientOf(manager, "c.com");

        assertEquals(manager.size(), 2);
        verify(b).close();
        verify(a, never()).close();
    }

    @Test
    public void testIdleTenantEvictedAndClosed() throws IOException {

        TenantHttpClientManager manager = newManager(10);
        CloseableHttpClient a = clientOf(manager, "a.com");
        now.set(IDLE_TIMEOUT + 1);
        clientOf(manager, "b.com");

        verify(a).close();
        assertEquals(manager.size(), 1);
        // The tenant gets a fresh client when it comes back.
        assertNotSame(clientOf(manager, "a.com"), a);
    }

    @Test
    public void testActiveTenantNotEvictedByIdleTimeout() throws IOException {

        TenantHttpClientManager manager = newManager(10);
        TenantHttpClientManager.Lease lease = manager.acquire("a.com");
        now.set(IDLE_TIMEOUT * 5);
        clientOf(manager, "b.com");

        verify(lease.getClient(), never()).close();
        assertEquals(manager.size(), 2);
        lease.close();
    }

    @Test
    public void testEvictedClientClosedOnlyAfterInFlightRequestFinishes() throws IOException {

        TenantHttpClientManager manager = newManager(1);
        TenantHttpClientManager.Lease lease = manager.acquire("a.com");
        CloseableHttpClient a = lease.getClient();
        clientOf(manager, "b.com"); // Evicts a by the cap while a request is running on it.

        verify(a, never()).close();
        lease.close();
        verify(a).close();
        lease.close(); // Releasing twice is harmless.
        verify(a).close();
    }

    @Test
    public void testCloseClosesAllClientsAndRejectsNewAcquires() throws IOException {

        TenantHttpClientManager manager = newManager(10);
        CloseableHttpClient a = clientOf(manager, "a.com");
        CloseableHttpClient b = clientOf(manager, "b.com");
        TenantHttpClientManager.Lease busy = manager.acquire("c.com");
        CloseableHttpClient c = busy.getClient();

        manager.close();

        verify(a).close();
        verify(b).close();
        verify(c, never()).close();
        busy.close();
        verify(c).close();
        assertEquals(manager.size(), 0);
        expectThrows(IllegalStateException.class, () -> manager.acquire("a.com"));
    }
}

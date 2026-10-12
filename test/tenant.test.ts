/**
 * Copyright (c) 2026 HOOX · HOOX · jango-blockchained (hoox-sh)
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, test, beforeEach, mock } from "bun:test";
import d1Worker, { __resetTenantSchemaCacheForTest } from "../src/index.js";
import { computeDashboardStats } from "../src/stats.js";

const TEST_INTERNAL_KEY = "test-internal-key";
const TENANT = "acme";

type Recorded = { sql: string; binds: unknown[] };

/** Mock DB that records every prepared statement + binds. */
function createRecordingDB(tables: string[] = []) {
  const recorded: Recorded[] = [];
  const okAll = (results: unknown[] = []) => ({
    success: true,
    error: null,
    results,
  });
  const makeStmt = (sql: string): any => {
    const stmt: any = {
      bind: mock((...args: unknown[]) => {
        recorded.push({ sql, binds: args });
        return stmt;
      }),
      run: mock(() => {
        recorded.push({ sql, binds: [] });
        return Promise.resolve({
          success: true,
          error: null,
          meta: { changes: 1 },
        });
      }),
      all: mock(() => {
        if (/sqlite_master/i.test(sql)) {
          return Promise.resolve(okAll(tables.map((name) => ({ name }))));
        }
        return Promise.resolve(okAll([]));
      }),
      first: mock(() => Promise.resolve(null)),
    };
    return stmt;
  };
  return {
    recorded,
    prepare: mock((sql: string) => makeStmt(sql)),
    batch: mock(() => Promise.resolve([])),
  };
}

const createMockKV = () => ({
  get: mock((_key: string) => Promise.resolve<string | null>(null)),
  put: mock((_k: string, _v: string) => Promise.resolve()),
  list: mock((_options?: { prefix?: string }) =>
    Promise.resolve({ keys: [] as { name: string }[] })
  ),
  delete: mock(() => Promise.resolve()),
});

const createCtx = () => ({ waitUntil: mock(() => {}) });

function tenantEnv(db: any, kv: any) {
  return {
    DB: db,
    INTERNAL_KEY_BINDING: TEST_INTERNAL_KEY,
    CONFIG_KV: kv,
    TENANT_ID: TENANT,
    TENANT_MODE: "true",
  };
}

function plainEnv(db: any, kv: any) {
  return {
    DB: db,
    INTERNAL_KEY_BINDING: TEST_INTERNAL_KEY,
    CONFIG_KV: kv,
  };
}

const authHeaders = {
  "Content-Type": "application/json",
  "X-Internal-Auth-Key": TEST_INTERNAL_KEY,
};

describe("d1-worker tenant row isolation", () => {
  beforeEach(() => {
    __resetTenantSchemaCacheForTest();
  });

  test("insert-trade stamps the env tenant", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/rpc/insert-trade", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          exchange: "mexc",
          symbol: "BTCUSDT",
          action: "LONG",
          quantity: 1,
        }),
      }),
      tenantEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(200);
    const insert = db.recorded.find((r) => /INSERT INTO trades/i.test(r.sql));
    expect(insert).toBeDefined();
    expect(insert!.sql).toContain("tenant_id");
    expect(insert!.binds[insert!.binds.length - 1]).toBe(TENANT);
  });

  test("insert-trade without flag stamps empty tenant", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/rpc/insert-trade", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          exchange: "mexc",
          symbol: "BTCUSDT",
          action: "LONG",
          quantity: 1,
        }),
      }),
      plainEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(200);
    const insert = db.recorded.find((r) => /INSERT INTO trades/i.test(r.sql));
    expect(insert).toBeDefined();
    expect(insert!.binds[insert!.binds.length - 1]).toBe("");
  });

  test("list-open-positions filters by tenant when flagged", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/rpc/list-open-positions", {
        method: "GET",
        headers: { "X-Internal-Auth-Key": TEST_INTERNAL_KEY },
      }),
      tenantEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(200);
    const sel = db.recorded.find((r) => /FROM positions/i.test(r.sql));
    expect(sel).toBeDefined();
    expect(sel!.sql).toContain("tenant_id = ?");
    expect(sel!.binds).toContain(TENANT);
  });

  test("list-open-positions unscoped without flag", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/rpc/list-open-positions", {
        method: "GET",
        headers: { "X-Internal-Auth-Key": TEST_INTERNAL_KEY },
      }),
      plainEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(200);
    const sel = db.recorded.find((r) => /FROM positions/i.test(r.sql));
    expect(sel).toBeDefined();
    expect(sel!.sql).not.toContain("tenant_id");
  });

  test("POST list-signals keeps POST-body tenant (single read)", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/rpc/list-signals", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ limit: 5, tenantId: "shared-1" }),
      }),
      plainEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(200);
    const sel = db.recorded.find((r) => /FROM trade_signals/i.test(r.sql));
    expect(sel).toBeDefined();
    expect(sel!.sql).toContain("tenant_id = ?");
    expect(sel!.binds).toContain("shared-1");
  });

  test("POST list-system-logs keeps POST-body tenant (single read)", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/rpc/list-system-logs", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ limit: 5, tenantId: "shared-2" }),
      }),
      plainEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(200);
    const sel = db.recorded.find((r) => /FROM system_logs/i.test(r.sql));
    expect(sel).toBeDefined();
    expect(sel!.sql).toContain("tenant_id = ?");
    expect(sel!.binds).toContain("shared-2");
  });

  test("free-form /query is rejected in tenant mode", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/query", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          query: "SELECT id FROM trade_requests WHERE id = ?",
          params: [1],
        }),
      }),
      tenantEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error?: string; message?: string };
    expect(JSON.stringify(body)).toContain("/rpc/");
  });

  test("free-form /batch is rejected in tenant mode", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/batch", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          statements: [
            {
              query: "SELECT id FROM trade_requests WHERE id = ?",
              params: [1],
            },
          ],
        }),
      }),
      tenantEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(403);
  });

  test("free-form /query still works without flag", async () => {
    const db = createRecordingDB();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/query", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          query: "SELECT id FROM trade_requests WHERE id = ?",
          params: [1],
        }),
      }),
      plainEnv(db, createMockKV()),
      createCtx()
    );
    expect(res.status).toBe(200);
  });

  test("startup migration adds tenant columns once per isolate", async () => {
    const db = createRecordingDB(["trades", "positions"]);
    const env = tenantEnv(db, createMockKV());
    const ctx = createCtx();
    const mkReq = () =>
      new Request("https://d1.local/rpc/list-open-positions", {
        method: "GET",
        headers: { "X-Internal-Auth-Key": TEST_INTERNAL_KEY },
      });
    await (d1Worker as any).fetch(mkReq(), env, ctx);
    await (d1Worker as any).fetch(mkReq(), env, ctx);
    const alters = db.recorded.filter((r) => /ALTER TABLE/i.test(r.sql));
    // One ALTER per existing table, issued only on the first request (cached).
    expect(alters.length).toBe(2);
    expect(alters.every((a) => /ADD COLUMN tenant_id/i.test(a.sql))).toBe(true);
    const indexes = db.recorded.filter((r) => /CREATE INDEX/i.test(r.sql));
    expect(indexes.length).toBe(2);
  });

  test("settings KV list is tenant-scoped", async () => {
    const db = createRecordingDB();
    const kv = createMockKV();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/api/settings", {
        method: "GET",
        headers: { "X-Internal-Auth-Key": TEST_INTERNAL_KEY },
      }),
      tenantEnv(db, kv),
      createCtx()
    );
    expect(res.status).toBe(200);
    expect(kv.list.mock.calls.length).toBeGreaterThan(0);
    for (const call of kv.list.mock.calls) {
      expect(String(call[0]?.prefix ?? "")).toStartWith(`t/${TENANT}/`);
    }
  });

  test("settings PUT stores under tenant scope", async () => {
    const db = createRecordingDB();
    const kv = createMockKV();
    const res = await (d1Worker as any).fetch(
      new Request("https://d1.local/api/settings", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ key: "global:foo", value: { a: 1 } }),
      }),
      tenantEnv(db, kv),
      createCtx()
    );
    expect(res.status).toBe(200);
    expect(kv.put.mock.calls.length).toBe(1);
    expect(String(kv.put.mock.calls[0][0])).toBe(`t/${TENANT}/global:foo`);
  });

  test("stats aggregates scope by tenant when given", async () => {
    const db = createRecordingDB();
    // Mock batch: 6 aggregate results like the existing stats tests.
    (db.batch as any).mockImplementation(() =>
      Promise.resolve([
        { success: true, results: [{ count: 1 }] },
        { success: true, results: [{ count: 1 }] },
        { success: true, results: [{ count: 1 }] },
        { success: true, results: [{ count: 1 }] },
        { success: true, results: [{ count: 1 }] },
        { success: true, results: [{ total: 5 }] },
      ])
    );
    const out = await computeDashboardStats(db as any, TENANT);
    expect("stats" in out).toBe(true);
    const stmts = db.prepare.mock.calls.map((c: any[]) => String(c[0]));
    expect(stmts.length).toBe(6);
    for (const sql of stmts) {
      expect(sql).toContain("tenant_id = ?");
    }
  });

  test("stats aggregates stay unscoped without tenant", async () => {
    const db = createRecordingDB();
    (db.batch as any).mockImplementation(() =>
      Promise.resolve([
        { success: true, results: [{ count: 0 }] },
        { success: true, results: [{ count: 0 }] },
        { success: true, results: [{ count: 0 }] },
        { success: true, results: [{ count: 0 }] },
        { success: true, results: [{ count: 0 }] },
        { success: true, results: [{ total: 0 }] },
      ])
    );
    const out = await computeDashboardStats(db as any);
    expect("stats" in out).toBe(true);
    const stmts = db.prepare.mock.calls.map((c: any[]) => String(c[0]));
    for (const sql of stmts) {
      expect(sql).not.toContain("tenant_id");
    }
  });
});

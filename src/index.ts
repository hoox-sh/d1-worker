/**
 * Copyright (c) 2026 HOOX · HOOX · jango-blockchained (hoox-sh)
 * SPDX-License-Identifier: Apache-2.0
 */

import type { D1Result } from "@cloudflare/workers-types";
import {
  Errors,
  createJsonResponse,
  toError,
} from "@hoox-sh/hoox-shared/errors";
import {
  createRouter,
  type MiddlewareHandler,
} from "@hoox-sh/hoox-shared/router";
import type { QueryPayload, BatchPayload } from "@hoox-sh/hoox-shared/types";
import { trackAnalytics } from "@hoox-sh/hoox-shared/analytics";
import {
  createLogger,
  createInternalAuthMiddleware,
  corsHeaders,
  resolveCorsOptions,
  internalCorsHeaders,
  withRequestLog,
  wrapWithSecurityHeaders,
  safeWaitUntil,
  type Logger,
} from "@hoox-sh/hoox-shared/middleware";
import { healthCheck } from "@hoox-sh/hoox-shared/health";
import {
  D1_READ_AUTH_KEY_FIELDS,
  D1_WRITE_AUTH_KEY_FIELDS,
} from "@hoox-sh/hoox-shared/service-bindings";
import { computeDashboardStats } from "./stats";
import {
  effectiveTenantId,
  isTenantFlagOn,
  scopeKey,
  type TenantEnv,
} from "@hoox-sh/hoox-shared/tenant";

const logger = createLogger({ service: "d1-worker", module: "router" });

// --- Type Definitions ---

export interface Env extends Cloudflare.Env {
  DB: D1Database;
  CONFIG_KV: KVNamespace;
  LOG_LIMIT?: string; // Optional binding, defaults to "50"
  /** Opt-in tenant isolation (see @hoox-sh/hoox-shared/tenant). Absent = self-host default. */
  TENANT_ID?: string;
  TENANT_MODE?: string;
}

// Known KV key prefixes the dashboard reads/writes. Mirrors the prefix list
// in workers/dashboard/src/app/api/settings/route.ts — keep them in sync.
const KNOWN_PREFIXES = [
  "global:",
  "webhook:",
  "trade:",
  "agent:",
  "bot:",
  "email:",
  "database:",
  "retention:",
  "routing:",
  "behavior:",
  "cron:",
  "ai:",
] as const;

type KnownPrefix = (typeof KNOWN_PREFIXES)[number];

function hasKnownPrefix(key: string): boolean {
  return KNOWN_PREFIXES.some((prefix) => key.startsWith(prefix));
}

// --- Security Helpers ---

const TABLE_ALLOWLIST = [
  "trade_signals",
  "trades",
  "positions",
  "balances",
  "system_logs",
  "trade_requests",
  "trade_responses",
] as const;

/** Schema / side-effect keywords blocked at the parser level (README firewall). */
const FORBIDDEN_SQL_KEYWORDS = [
  "DROP",
  "PRAGMA",
  "ALTER",
  "TRUNCATE",
  "VACUUM",
  "ATTACH",
  "DETACH",
  "CREATE",
  "GRANT",
  "REVOKE",
  "REINDEX",
  "ANALYZE",
] as const;

/** Hard limits to bound CPU / D1 work from a single request. */
const MAX_SQL_LENGTH = 8_192;
const MAX_BATCH_STATEMENTS = 50;
const MAX_PARAMS_PER_STATEMENT = 64;

// ── Tenant row isolation ───────────────────────────────────────────
// Every allowlisted table carries a `tenant_id` column (fresh DBs via
// workers/trade-worker/schema.sql; existing DBs via ensureTenantSchema
// below). Writes stamp the effective tenant; reads filter on it. When the
// flag is off all helpers are identity and SQL is unscoped (self-host).

const TENANT_TABLES: readonly string[] = TABLE_ALLOWLIST;

let tenantSchemaReady: Promise<void> | null = null;

/**
 * Idempotent startup migration: ADD COLUMN tenant_id + index on each
 * existing allowlisted table. Cached per isolate; never throws (logs and
 * continues — a missing column only matters when scoping is active, and
 * the scoped statements would then surface the real error).
 */
function ensureTenantSchema(db: D1Database): Promise<void> {
  if (!tenantSchemaReady) {
    tenantSchemaReady = (async () => {
      try {
        const existing = await db
          .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
          .all<{ name: string }>();
        const names = new Set(
          (existing.results ?? []).map((r) => String(r.name).toLowerCase())
        );
        for (const table of TENANT_TABLES) {
          if (!names.has(table.toLowerCase())) continue;
          try {
            await db
              .prepare(
                `ALTER TABLE ${table} ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`
              )
              .run();
          } catch (error) {
            // Duplicate-column on re-run; anything else is logged below.
            if (!/duplicate column name/i.test(toError(error))) throw error;
          }
          await db
            .prepare(
              `CREATE INDEX IF NOT EXISTS idx_${table}_tenant_id ON ${table} (tenant_id)`
            )
            .run();
        }
      } catch (error) {
        logger.warn("tenant schema ensure failed", { error: toError(error) });
      }
    })();
  }
  return tenantSchemaReady;
}

/** Test hook: reset the cached migration promise between cases. */
export function __resetTenantSchemaCacheForTest(): void {
  tenantSchemaReady = null;
}

/**
 * Effective tenant for a D1 read/write: the env tenant when TENANT_MODE is
 * on (authoritative, throws when misconfigured), else a caller-supplied
 * `tenantId` (shared-DB path), else "" (unscoped self-host rows).
 */
function resolveRowTenant(env: Env, msg?: { tenantId?: unknown }): string {
  return effectiveTenantId(env as TenantEnv, msg) ?? "";
}

/** `AND tenant_id = ?` fragment + bind value, or empty when unscoped. */
function tenantFilter(tenantId: string): { sql: string; binds: string[] } {
  return tenantId
    ? { sql: "AND tenant_id = ?", binds: [tenantId] }
    : { sql: "", binds: [] };
}

type ValidationResult = {
  valid: boolean;
  error?: string;
  statusCode?: number;
};

/**
 * Strips SQL comments from a query string to prevent comment-based bypass
 * of validation checks. Handles both single-line (--) and multi-line (/* * /) comments.
 */
function stripSqlComments(sql: string): string {
  let result = "";
  let i = 0;
  while (i < sql.length) {
    // Single-line comment: --
    if (sql[i] === "-" && sql[i + 1] === "-") {
      i += 2;
      while (i < sql.length && sql[i] !== "\n") i++;
      continue;
    }
    // Multi-line comment: /* */
    if (sql[i] === "/" && sql[i + 1] === "*") {
      i += 2;
      while (i < sql.length && !(sql[i] === "*" && sql[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    result += sql[i];
    i++;
  }
  return result;
}

/**
 * Shared structural checks applied to every free-form SQL string before
 * type-specific validation (SELECT vs write).
 */
function assertSqlStructure(cleaned: string): ValidationResult {
  if (cleaned.length > MAX_SQL_LENGTH) {
    return {
      valid: false,
      error: `SQL statement exceeds max length (${MAX_SQL_LENGTH} chars)`,
      statusCode: 400,
    };
  }

  // Multi-statement abuse: reject any non-trailing semicolon. Allows a
  // single trailing `;` for clients that always terminate statements.
  const withoutTrailingSemi = cleaned.replace(/;\s*$/, "");
  if (withoutTrailingSemi.includes(";")) {
    return {
      valid: false,
      error: "Multi-statement SQL is not allowed",
      statusCode: 403,
    };
  }

  // Keyword firewall (defense-in-depth even when query type is SELECT)
  for (const kw of FORBIDDEN_SQL_KEYWORDS) {
    if (new RegExp(`\\b${kw}\\b`, "i").test(cleaned)) {
      return {
        valid: false,
        error: `Forbidden SQL keyword: ${kw}`,
        statusCode: 403,
      };
    }
  }

  // Reject string literals — all values must use ? placeholders
  if (/'([^']|'')*'/.test(cleaned)) {
    return {
      valid: false,
      error:
        "String literals not allowed in query. Use parameter placeholders (?) instead.",
      statusCode: 400,
    };
  }

  // Reject double-quoted identifiers
  if (/"[^"]*"/.test(cleaned)) {
    return {
      valid: false,
      error: "Quoted identifiers not allowed in query.",
      statusCode: 400,
    };
  }

  return { valid: true };
}

function extractReferencedTables(cleaned: string): Set<string> {
  const tableRegex = /\b(?:FROM|JOIN|INTO|UPDATE)\s+([a-zA-Z0-9_]+)/gi;
  const tablesFound = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = tableRegex.exec(cleaned)) !== null) {
    const table = match[1];
    if (table) tablesFound.add(table.toLowerCase());
  }
  return tablesFound;
}

function assertTablesAllowlisted(tables: Set<string>): ValidationResult {
  for (const table of tables) {
    if (!(TABLE_ALLOWLIST as readonly string[]).includes(table)) {
      return {
        valid: false,
        error: `Unauthorized table access: ${table}`,
        statusCode: 403,
      };
    }
  }
  return { valid: true };
}

/**
 * Validates a SQL query for security (SELECT path used by /query and /batch).
 *
 * SECURITY MODEL:
 * - SQL comments are stripped before validation to prevent bypasses
 * - Only SELECT queries are allowed (writes use named /rpc/* endpoints)
 * - Multi-statement SQL rejected (semicolon abuse)
 * - Destructive keywords blocked at the parser level
 * - String literals rejected -> all values must use ? placeholders
 * - Table names validated against allowlist -> 403 Forbidden
 * - UNION and subqueries in WHERE/HAVING are restricted -> 403 Forbidden
 */
function validateQuery(query: string): ValidationResult {
  if (typeof query !== "string" || !query.trim()) {
    return {
      valid: false,
      error: "Query must be a non-empty string",
      statusCode: 400,
    };
  }

  const cleaned = stripSqlComments(query);
  const structure = assertSqlStructure(cleaned);
  if (!structure.valid) return structure;

  const normalized = cleaned.trim().toUpperCase();
  const queryType = normalized.split(/\s+/)[0] ?? "";
  if (queryType !== "SELECT") {
    return {
      valid: false,
      error: `Unsupported query type: ${queryType}. Only SELECT queries are allowed.`,
      statusCode: 400,
    };
  }

  const tables = assertTablesAllowlisted(extractReferencedTables(cleaned));
  if (!tables.valid) return tables;

  // UNION can exfiltrate across tables even when both are allowlisted
  if (/\bUNION\b/i.test(cleaned)) {
    return {
      valid: false,
      error: "UNION not allowed in SELECT queries",
      statusCode: 403,
    };
  }

  // Nested SELECT complexity / DoS risk
  if (/\b(WHERE|HAVING)\s*\(/i.test(cleaned)) {
    return {
      valid: false,
      error: "Subqueries in WHERE/HAVING not allowed",
      statusCode: 403,
    };
  }

  return { valid: true };
}

/**
 * Validates INSERT/UPDATE/DELETE/REPLACE writes from trusted internal callers.
 * Defense-in-depth: keyword firewall + table allowlist + no string literals.
 */
function validateWriteQuery(query: string): ValidationResult {
  if (typeof query !== "string" || !query.trim()) {
    return {
      valid: false,
      error: "Write query must be a non-empty string",
      statusCode: 400,
    };
  }

  const cleaned = stripSqlComments(query);
  const structure = assertSqlStructure(cleaned);
  if (!structure.valid) return structure;

  const normalized = cleaned.trim().toUpperCase();
  const queryType = normalized.split(/\s+/)[0] ?? "";

  if (!["INSERT", "UPDATE", "DELETE", "REPLACE"].includes(queryType)) {
    return {
      valid: false,
      error: `Unsupported write type: ${queryType}`,
      statusCode: 400,
    };
  }

  return assertTablesAllowlisted(extractReferencedTables(cleaned));
}

/** Validate bind-parameter array size before handing off to D1. */
function validateParams(params: unknown): ValidationResult {
  if (params == null) return { valid: true };
  if (!Array.isArray(params)) {
    return {
      valid: false,
      error: "params must be an array",
      statusCode: 400,
    };
  }
  if (params.length > MAX_PARAMS_PER_STATEMENT) {
    return {
      valid: false,
      error: `Too many params (max ${MAX_PARAMS_PER_STATEMENT})`,
      statusCode: 400,
    };
  }
  return { valid: true };
}

function prepareValidatedWrite(env: Env, query: string): D1PreparedStatement {
  const validation = validateWriteQuery(query);
  if (!validation.valid) {
    throw new Error(validation.error || "Write query validation failed");
  }
  return env.DB.prepare(query);
}

const MAX_JSON_BODY_BYTES = 1024 * 1024; // 1 MiB

/**
 * Checks that the request has a JSON Content-Type and a reasonable body size.
 * Returns a Response (error) if validation fails, or null if the body is acceptable.
 *
 * Content-Length is an early reject when present; callers that need a hard
 * cap regardless of headers should read via `readJsonBodyWithLimit`.
 */
function requireJsonBody(request: Request): Response | null {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.includes("application/json")) {
    return Errors.badRequest("Content-Type must be application/json");
  }
  const contentLength = request.headers.get("Content-Length");
  if (contentLength) {
    const size = parseInt(contentLength, 10);
    if (isNaN(size) || size > MAX_JSON_BODY_BYTES) {
      return Errors.badRequest("Request body too large (max 1MB)");
    }
  }
  return null;
}

/**
 * Parse JSON body with a hard byte cap (does not trust Content-Length alone).
 */
async function readJsonBodyWithLimit(
  request: Request,
  maxBytes: number = MAX_JSON_BODY_BYTES
): Promise<{ ok: true; value: unknown } | { ok: false; response: Response }> {
  const reader = request.body?.getReader();
  if (!reader) {
    return { ok: false, response: Errors.badRequest("Empty request body") };
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          /* ignore */
        }
        return {
          ok: false,
          response: Errors.badRequest("Request body too large (max 1MB)"),
        };
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  try {
    const text = new TextDecoder().decode(merged);
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return {
      ok: false,
      response: Errors.badRequest("Invalid JSON in request body"),
    };
  }
}

// --- Worker Definition ---

const router = createRouter<Env>();
// Cast: createInternalAuthMiddleware returns MiddlewareHandler<InternalAuthEnv>
// but our router is typed for MiddlewareHandler<Env>. The middleware only
// reads `INTERNAL_KEY_BINDING` which is present on both types.
const requireReadAuth = createInternalAuthMiddleware(
  D1_READ_AUTH_KEY_FIELDS
) as unknown as MiddlewareHandler<Env>;
const requireWriteAuth = createInternalAuthMiddleware(
  D1_WRITE_AUTH_KEY_FIELDS
) as unknown as MiddlewareHandler<Env>;

// Health check endpoint
router.get(
  "/health",
  async (_request: Request, env: Env, _ctx: ExecutionContext) => {
    try {
      await env.DB.prepare("SELECT 1").first();
    } catch {
      return Errors.internal("Database unreachable");
    }
    return healthCheck({ worker: "d1-worker" });
  }
);

// Query endpoint
router.post(
  "/query",
  async (request: Request, env: Env, ctx: ExecutionContext) => {
    const startTime = Date.now();

    // Free-form SELECT cannot be tenant-rewritten safely: reject in tenant
    // mode so cross-tenant reads must go through the scoped /rpc/* set.
    if (isTenantFlagOn(env)) {
      return Errors.forbidden(
        "Free-form /query is disabled in tenant mode. Use the tenant-scoped /rpc/* endpoints."
      );
    }

    try {
      const bodyGuard = requireJsonBody(request);
      if (bodyGuard) return bodyGuard;

      const parsedBody = await readJsonBodyWithLimit(request);
      if (!parsedBody.ok) return parsedBody.response;
      const payload = parsedBody.value as QueryPayload;

      if (!payload || typeof payload.query !== "string") {
        return Errors.badRequest(
          "Invalid payload: missing or invalid 'query' field."
        );
      }

      const params = payload.params || [];

      // /query is READ-ONLY free-form SELECT. Prefer named /rpc/* for
      // known hot paths (list-signals, list-system-logs, inserts).
      // Free-form writes are permanently rejected (410 USE_NAMED_RPC).
      const queryType = payload.query.trim().split(/\s+/)[0]?.toUpperCase();
      if (queryType !== "SELECT") {
        logger.warn("Rejected free-form write on /query", {
          queryType,
          prefix: payload.query.substring(0, 40),
        });
        return createJsonResponse(
          {
            success: false,
            error:
              "Free-form writes are disabled on /query. Use named RPC: " +
              "/rpc/insert-trade, /rpc/upsert-position, /rpc/insert-signal, " +
              "/rpc/insert-system-log. Prefer /rpc/list-signals, " +
              "/rpc/list-system-logs, and /rpc/list-open-positions for those reads.",
            code: "USE_NAMED_RPC",
          },
          410
        );
      }

      const validation = validateQuery(payload.query);
      if (!validation.valid) {
        logger.warn("Query validation failed", {
          error: validation.error,
          query: payload.query,
        });
        const statusCode = validation.statusCode || 403;
        if (statusCode === 400) {
          return Errors.badRequest(
            validation.error || "Query validation failed"
          );
        }
        return Errors.forbidden(validation.error || "Query validation failed");
      }

      const paramsCheck = validateParams(params);
      if (!paramsCheck.valid) {
        return Errors.badRequest(paramsCheck.error || "Invalid params");
      }

      logger.info("Executing D1 query", { query: payload.query });
      const stmt = env.DB.prepare(payload.query).bind(...params);

      const result: D1Result<Record<string, unknown>> = await stmt.all();
      logger.info("D1 SELECT result", { success: result.success });
      if (!result.success) {
        throw new Error(result.error || "D1 SELECT query failed");
      }
      const response = createJsonResponse({
        success: true,
        results: result.results,
      });

      // Track SELECT analytics (non-blocking)
      const selectLatency = Date.now() - startTime;
      safeWaitUntil(
        ctx,
        trackAnalytics(env, "/track/api-call", {
          worker: "d1-worker",
          endpoint: "/query",
          latencyMs: selectLatency,
          success: true,
          queryType: "SELECT",
        }),
        (err) => logger.error("trackAnalytics failed", { error: String(err) })
      );

      return response;
    } catch (error) {
      const errorMsg = toError(error);
      logger.error("Query error", { error: errorMsg });

      // Track failed API call (non-blocking)
      const latencyMs = Date.now() - startTime;
      safeWaitUntil(
        ctx,
        trackAnalytics(env, "/track/api-call", {
          worker: "d1-worker",
          endpoint: "/query",
          latencyMs,
          success: false,
        }),
        (err) => logger.error("trackAnalytics failed", { error: String(err) })
      );

      return Errors.internal(errorMsg);
    }
  },
  [requireReadAuth]
);

// Batch endpoint
router.post(
  "/batch",
  async (request: Request, env: Env, ctx: ExecutionContext) => {
    const startTime = Date.now();

    // Same tenant rationale as /query: fixed /rpc/* templates only.
    if (isTenantFlagOn(env)) {
      return Errors.forbidden(
        "Free-form /batch is disabled in tenant mode. Use the tenant-scoped /rpc/* endpoints."
      );
    }

    try {
      const bodyGuard = requireJsonBody(request);
      if (bodyGuard) return bodyGuard;

      const parsedBody = await readJsonBodyWithLimit(request);
      if (!parsedBody.ok) return parsedBody.response;
      const payload = parsedBody.value as BatchPayload;

      if (!payload || !Array.isArray(payload.statements)) {
        return Errors.badRequest("Missing or invalid statements array");
      }

      if (payload.statements.length === 0) {
        return Errors.badRequest("statements array must not be empty");
      }

      if (payload.statements.length > MAX_BATCH_STATEMENTS) {
        return Errors.badRequest(
          `Batch exceeds max statements (max ${MAX_BATCH_STATEMENTS})`
        );
      }

      // /batch is READ-ONLY (SELECT only). Mutations must use /rpc/* routes.
      for (const stmt of payload.statements) {
        if (typeof stmt.query !== "string" || !stmt.query.trim()) {
          return Errors.badRequest("Each statement must have a 'query' field");
        }

        const isSelect = stmt.query.trim().toUpperCase().startsWith("SELECT");
        if (!isSelect) {
          return createJsonResponse(
            {
              success: false,
              error:
                "Free-form writes are disabled on /batch. Use named /rpc/* endpoints.",
              code: "USE_NAMED_RPC",
            },
            410
          );
        }

        const validation = validateQuery(stmt.query);
        if (!validation.valid) {
          logger.warn("Batch statement validation failed", {
            error: validation.error,
            query: stmt.query,
          });
          const statusCode = validation.statusCode || 403;
          if (statusCode === 400) {
            return Errors.badRequest(
              validation.error || "Statement validation failed"
            );
          }
          return Errors.forbidden(
            validation.error || "Statement validation failed"
          );
        }

        const paramsCheck = validateParams(stmt.params);
        if (!paramsCheck.valid) {
          return Errors.badRequest(paramsCheck.error || "Invalid params");
        }
      }

      // Use native DB.batch() for atomic, faster execution
      const stmts = payload.statements.map((s) => {
        const prepared = env.DB.prepare(s.query);
        if (s.params && s.params.length > 0) {
          return prepared.bind(...s.params);
        }
        return prepared;
      });
      const results = await env.DB.batch(stmts);

      // Check for partial failures
      const failedResult = results.find((r) => r.error);
      const allSuccess = !failedResult;

      // Track API call analytics (non-blocking)
      const latencyMs = Date.now() - startTime;
      safeWaitUntil(
        ctx,
        trackAnalytics(env, "/track/api-call", {
          worker: "d1-worker",
          endpoint: "/batch",
          latencyMs,
          success: allSuccess,
        }),
        (err) => logger.error("trackAnalytics failed", { error: String(err) })
      );

      if (!allSuccess) {
        return createJsonResponse({
          success: false,
          error: failedResult.error || "Batch statement failed",
          results,
        });
      }

      return createJsonResponse({ success: true, results });
    } catch (error) {
      const errorMsg = toError(error);
      logger.error("Batch error", { error: errorMsg });

      // Track failed API call (non-blocking)
      const latencyMs = Date.now() - startTime;
      safeWaitUntil(
        ctx,
        trackAnalytics(env, "/track/api-call", {
          worker: "d1-worker",
          endpoint: "/batch",
          latencyMs,
          success: false,
        }),
        (err) => logger.error("trackAnalytics failed", { error: String(err) })
      );

      return Errors.internal(errorMsg);
    }
  },
  [requireReadAuth]
);

// Dashboard settings endpoint
router.get(
  "/api/settings",
  async (_request: Request, env: Env, _ctx: ExecutionContext) => {
    try {
      const settings: Record<string, unknown> = {};

      const prefixes: readonly KnownPrefix[] = KNOWN_PREFIXES;

      // Tenant-scoped list prefixes when the flag is on (identity otherwise).
      const tenantEnv = env as TenantEnv;
      const lists = await Promise.all(
        prefixes.map((prefix) =>
          env.CONFIG_KV.list({ prefix: scopeKey(tenantEnv, prefix) })
        )
      );

      // Collect all key names from all lists, stripping the tenant scope
      // back to canonical keys so clients see stable key shapes.
      const scopePrefix = isTenantFlagOn(env)
        ? scopeKey(tenantEnv, "").replace(/\/$/, "/")
        : "";
      const allKeys: string[] = [];
      for (const list of lists) {
        for (const k of list.keys) {
          allKeys.push(
            scopePrefix && k.name.startsWith(scopePrefix)
              ? k.name.slice(scopePrefix.length)
              : k.name
          );
        }
      }

      // Get all values in parallel (re-scope canonical keys for the read)
      const values = await Promise.all(
        allKeys.map((key) => env.CONFIG_KV.get(scopeKey(tenantEnv, key)))
      );

      // Build settings object
      for (let i = 0; i < allKeys.length; i++) {
        const key = allKeys[i];
        const data = values[i];
        if (key && data) {
          try {
            settings[key] = JSON.parse(data);
          } catch {
            settings[key] = data;
          }
        }
      }

      return createJsonResponse({ success: true, settings });
    } catch (error) {
      const errorMsg = toError(error);
      logger.error("Settings error", { error: errorMsg });
      return Errors.internal(errorMsg);
    }
  },
  [requireReadAuth]
);

// Dashboard settings POST endpoint
router.post(
  "/api/settings",
  async (request: Request, env: Env, _ctx: ExecutionContext) => {
    try {
      const bodyGuard = requireJsonBody(request);
      if (bodyGuard) return bodyGuard;

      const parsedBody = await readJsonBodyWithLimit(request);
      if (!parsedBody.ok) return parsedBody.response;
      const payload = parsedBody.value as Record<string, unknown>;

      const key = payload.key;
      if (!key || typeof key !== "string") {
        return Errors.badRequest("Missing key");
      }

      // The dashboard already sends fully-prefixed keys (e.g. "global:kill_switch").
      // Store the key as-is to avoid double-prefixing. Validate it starts with one
      // of the known prefixes to keep the KV namespace well-formed, then apply
      // the tenant scope (identity when the flag is off).
      if (!hasKnownPrefix(key)) {
        return Errors.badRequest(
          `Key must start with one of: ${KNOWN_PREFIXES.join(", ")}`
        );
      }

      await env.CONFIG_KV.put(
        scopeKey(env as TenantEnv, key),
        JSON.stringify(payload.value ?? {})
      );

      return createJsonResponse({ success: true, key });
    } catch (error) {
      const errorMsg = toError(error);
      logger.error("Settings POST error", { error: errorMsg });
      return Errors.internal(errorMsg);
    }
  },
  [requireWriteAuth]
);

// --- Extracted Handler Functions ---

async function handleGetBalances(
  request: Request,
  env: Env,
  logger: Logger
): Promise<Response> {
  try {
    // Env tenant wins when the flag is on; else an explicit ?tenantId=.
    const rowTenant = resolveRowTenant(env, {
      tenantId: new URL(request.url).searchParams.get("tenantId"),
    });
    const scope = tenantFilter(rowTenant);
    const latestSnapshots = await env.DB.prepare(
      `
    SELECT b.exchange, b.asset, b.total, b.timestamp
    FROM balances b
    INNER JOIN (
      SELECT exchange, asset, MAX(timestamp) as max_time
      FROM balances
      WHERE 1 = 1 ${scope.sql}
      GROUP BY exchange, asset
    ) latest ON b.exchange = latest.exchange AND b.asset = latest.asset AND b.timestamp = latest.max_time
    WHERE 1 = 1 ${scope.sql.replaceAll("tenant_id", "b.tenant_id")}
  `
    )
      .bind(...scope.binds, ...scope.binds)
      .all();

    const totalBalance = (latestSnapshots.results || []).reduce(
      (sum: number, row: Record<string, unknown>) => {
        return sum + ((row.total as number) || 0);
      },
      0
    );

    return createJsonResponse({
      success: true,
      totalBalance,
      balances: latestSnapshots.results || [],
    });
  } catch (error) {
    const errorMsg = toError(error);
    logger.error("Balances error", { error: errorMsg });
    return Errors.internal(errorMsg);
  }
}

async function handleGetPositions(
  request: Request,
  env: Env,
  logger: Logger
): Promise<Response> {
  try {
    // Fixed column list (no SELECT *) — same shape as /rpc/list-open-positions
    const rowTenant = resolveRowTenant(env, {
      tenantId: new URL(request.url).searchParams.get("tenantId"),
    });
    const scope = tenantFilter(rowTenant);
    const positionsData = await env.DB.prepare(
      `SELECT id, exchange, symbol, side, size, status, updated_at
       FROM positions
       WHERE status = 'OPEN' ${scope.sql}
       ORDER BY updated_at DESC`
    )
      .bind(...scope.binds)
      .all();

    return createJsonResponse({
      success: true,
      positions: positionsData.results || [],
    });
  } catch (error) {
    const errorMsg = toError(error);
    logger.error("Positions error", { error: errorMsg });
    return Errors.internal(errorMsg);
  }
}

// Dashboard balances endpoint
router.get(
  "/api/balances",
  async (request: Request, env: Env, _ctx: ExecutionContext) =>
    handleGetBalances(request, env, logger),
  [requireReadAuth]
);

// Dashboard positions endpoint
router.get(
  "/api/positions",
  async (request: Request, env: Env, _ctx: ExecutionContext) =>
    handleGetPositions(request, env, logger),
  [requireReadAuth]
);

// Dashboard-prefixed aliases for agent-worker compatibility
router.get(
  "/api/dashboard/balances",
  async (request: Request, env: Env, _ctx: ExecutionContext) =>
    handleGetBalances(request, env, logger),
  [requireReadAuth]
);

router.get(
  "/api/dashboard/positions",
  async (request: Request, env: Env, _ctx: ExecutionContext) =>
    handleGetPositions(request, env, logger),
  [requireReadAuth]
);

// Dashboard logs endpoint
router.get(
  "/api/logs",
  async (request: Request, env: Env, _ctx: ExecutionContext) => {
    try {
      const limit = Math.min(
        Math.max(parseInt(env.LOG_LIMIT || "50", 10) || 50, 1),
        1000
      );
      const rowTenant = resolveRowTenant(env, {
        tenantId: new URL(request.url).searchParams.get("tenantId"),
      });
      const scope = tenantFilter(rowTenant);
      const logsData = await env.DB.prepare(
        `SELECT id, timestamp, level, module, message, context FROM system_logs WHERE 1 = 1 ${scope.sql} ORDER BY timestamp DESC LIMIT ?`
      )
        .bind(...scope.binds, limit)
        .all();

      return createJsonResponse({
        success: true,
        logs: logsData.results || [],
      });
    } catch (error) {
      const errorMsg = toError(error);
      logger.error("Logs error", { error: errorMsg });
      return Errors.internal(errorMsg);
    }
  },
  [requireReadAuth]
);

// Dashboard stats endpoint
router.get(
  "/api/dashboard/stats",
  async (request: Request, env: Env, _ctx: ExecutionContext) => {
    const rowTenant = resolveRowTenant(env, {
      tenantId: new URL(request.url).searchParams.get("tenantId"),
    });
    const result = await computeDashboardStats(env.DB, rowTenant || undefined);
    if ("error" in result) {
      logger.error("Dashboard stats error", { error: result.error });
      return Errors.internal(result.error);
    }
    return createJsonResponse({ success: true, stats: result.stats });
  },
  [requireReadAuth]
);

// ── Named RPC endpoints ────────────────────────────────────────────
// Prefer fixed-template /rpc/* over free-form /query for hot paths
// (both writes and common list reads). Templates eliminate injection
// surface and keep the table allowlist implicit in the route.
// Free-form POST /query remains available for ad-hoc SELECTs.

const MAX_RPC_LIST_LIMIT = 100;
const MAX_RPC_LIST_OFFSET = 10_000;

async function rpcJsonBody(
  request: Request
): Promise<
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; response: Response }
> {
  const bodyGuard = requireJsonBody(request);
  if (bodyGuard) return { ok: false, response: bodyGuard };
  const parsed = await readJsonBodyWithLimit(request);
  if (!parsed.ok) return parsed;
  if (
    !parsed.value ||
    typeof parsed.value !== "object" ||
    Array.isArray(parsed.value)
  ) {
    return {
      ok: false,
      response: Errors.badRequest("Body must be a JSON object"),
    };
  }
  return { ok: true, value: parsed.value as Record<string, unknown> };
}

/**
 * Parse bound limit/offset from a JSON body or URL search params.
 * Caps limit at MAX_RPC_LIST_LIMIT and offset at MAX_RPC_LIST_OFFSET.
 */
function parseListPagination(
  source: Record<string, unknown> | URLSearchParams,
  defaultLimit: number
):
  | { ok: true; limit: number; offset: number }
  | { ok: false; response: Response } {
  const rawLimit =
    source instanceof URLSearchParams ? source.get("limit") : source.limit;
  const rawOffset =
    source instanceof URLSearchParams ? source.get("offset") : source.offset;

  let limit = defaultLimit;
  if (rawLimit !== null && rawLimit !== undefined && rawLimit !== "") {
    const n =
      typeof rawLimit === "number" ? rawLimit : parseInt(String(rawLimit), 10);
    if (!Number.isFinite(n) || n < 1) {
      return {
        ok: false,
        response: Errors.badRequest(
          `Invalid limit (must be 1-${MAX_RPC_LIST_LIMIT})`
        ),
      };
    }
    limit = Math.min(Math.floor(n), MAX_RPC_LIST_LIMIT);
  }

  let offset = 0;
  if (rawOffset !== null && rawOffset !== undefined && rawOffset !== "") {
    const n =
      typeof rawOffset === "number"
        ? rawOffset
        : parseInt(String(rawOffset), 10);
    if (!Number.isFinite(n) || n < 0) {
      return {
        ok: false,
        response: Errors.badRequest(
          `Invalid offset (must be 0-${MAX_RPC_LIST_OFFSET})`
        ),
      };
    }
    offset = Math.min(Math.floor(n), MAX_RPC_LIST_OFFSET);
  }

  return { ok: true, limit, offset };
}

/**
 * Parse bound limit/offset plus an optional caller-supplied `tenantId` from a
 * list RPC request. Reads the request stream exactly once — pagination and
 * tenant must come from the same read, otherwise a second read sees a
 * consumed stream (null) and silently drops the tenant filter on POST.
 */
async function parseListRpcParamsWithTenant(
  request: Request,
  defaultLimit: number
): Promise<
  | { ok: true; limit: number; offset: number; tenantId: unknown }
  | { ok: false; response: Response }
> {
  if (request.method === "GET") {
    const params = new URL(request.url).searchParams;
    const pagination = parseListPagination(params, defaultLimit);
    if (!pagination.ok) return pagination;
    return { ...pagination, tenantId: params.get("tenantId") };
  }
  // POST: empty body is allowed (defaults); otherwise JSON object
  if (!request.body) {
    const pagination = parseListPagination({}, defaultLimit);
    if (!pagination.ok) return pagination;
    return { ...pagination, tenantId: undefined };
  }
  const contentType = request.headers.get("Content-Type") || "";
  // Allow POST with no JSON when Content-Type is missing/empty (defaults)
  if (!contentType.includes("application/json")) {
    const contentLength = request.headers.get("Content-Length");
    if (!contentLength || contentLength === "0") {
      const pagination = parseListPagination({}, defaultLimit);
      if (!pagination.ok) return pagination;
      return { ...pagination, tenantId: undefined };
    }
    return {
      ok: false,
      response: Errors.badRequest("Content-Type must be application/json"),
    };
  }
  const body = await rpcJsonBody(request);
  if (!body.ok) return body;
  const pagination = parseListPagination(body.value, defaultLimit);
  if (!pagination.ok) return pagination;
  return { ...pagination, tenantId: body.value.tenantId };
}

/** POST /rpc/insert-trade — insert a executed trade row */
router.post(
  "/rpc/insert-trade",
  async (request: Request, env: Env, _ctx: ExecutionContext) => {
    const body = await rpcJsonBody(request);
    if (!body.ok) return body.response;
    const b = body.value;
    const id = typeof b.id === "string" ? b.id : crypto.randomUUID();
    const timestamp =
      typeof b.timestamp === "number"
        ? b.timestamp
        : Math.floor(Date.now() / 1000);
    const exchange = String(b.exchange ?? "");
    const symbol = String(b.symbol ?? "");
    const action = String(b.action ?? "");
    const quantity = Number(b.quantity);
    if (!exchange || !symbol || !action || !Number.isFinite(quantity)) {
      return Errors.badRequest("Required: exchange, symbol, action, quantity");
    }
    // Tenant stamp: env tenant when the flag is on, else caller-supplied, else "".
    const rowTenant = resolveRowTenant(env, b as { tenantId?: unknown });
    try {
      const result = await prepareValidatedWrite(
        env,
        `INSERT INTO trades (id, timestamp, exchange, symbol, action, quantity, price, leverage, status, raw_response, tenant_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          id,
          timestamp,
          exchange,
          symbol,
          action,
          quantity,
          b.price ?? null,
          b.leverage ?? null,
          String(b.status ?? "EXECUTED"),
          typeof b.raw_response === "string"
            ? b.raw_response
            : JSON.stringify(b.raw_response ?? null),
          rowTenant
        )
        .run();
      if (!result.success) {
        throw new Error(result.error || "insert-trade failed");
      }
      return createJsonResponse({
        success: true,
        id,
        changes: result.meta?.changes ?? null,
      });
    } catch (error) {
      logger.error("rpc/insert-trade failed", { error: toError(error) });
      return Errors.internal(toError(error));
    }
  },
  [requireWriteAuth]
);

/** POST /rpc/upsert-position — REPLACE a positions row */
router.post(
  "/rpc/upsert-position",
  async (request: Request, env: Env, _ctx: ExecutionContext) => {
    const body = await rpcJsonBody(request);
    if (!body.ok) return body.response;
    const b = body.value;
    const id = String(b.id ?? "");
    const exchange = String(b.exchange ?? "");
    const symbol = String(b.symbol ?? "");
    const side = String(b.side ?? "");
    const size = Number(b.size);
    const status = String(b.status ?? "OPEN");
    const updatedAt =
      typeof b.updated_at === "number"
        ? b.updated_at
        : Math.floor(Date.now() / 1000);
    if (!id || !exchange || !symbol || !side || !Number.isFinite(size)) {
      return Errors.badRequest("Required: id, exchange, symbol, side, size");
    }
    const rowTenant = resolveRowTenant(env, b as { tenantId?: unknown });
    try {
      const result = await prepareValidatedWrite(
        env,
        `REPLACE INTO positions (id, exchange, symbol, side, size, status, updated_at, tenant_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(id, exchange, symbol, side, size, status, updatedAt, rowTenant)
        .run();
      if (!result.success) {
        throw new Error(result.error || "upsert-position failed");
      }
      return createJsonResponse({
        success: true,
        id,
        changes: result.meta?.changes ?? null,
      });
    } catch (error) {
      logger.error("rpc/upsert-position failed", { error: toError(error) });
      return Errors.internal(toError(error));
    }
  },
  [requireWriteAuth]
);

/** POST /rpc/insert-signal — insert a trade_signals row */
router.post(
  "/rpc/insert-signal",
  async (request: Request, env: Env, _ctx: ExecutionContext) => {
    const body = await rpcJsonBody(request);
    if (!body.ok) return body.response;
    const b = body.value;
    const signalId =
      typeof b.signal_id === "string" ? b.signal_id : crypto.randomUUID();
    const timestamp = Number(b.timestamp);
    const symbol = String(b.symbol ?? "");
    const signalType = String(b.signal_type ?? "");
    if (!symbol || !signalType || !Number.isFinite(timestamp)) {
      return Errors.badRequest("Required: symbol, signal_type, timestamp");
    }
    const rowTenant = resolveRowTenant(env, b as { tenantId?: unknown });
    try {
      const result = await prepareValidatedWrite(
        env,
        `INSERT INTO trade_signals (signal_id, timestamp, symbol, signal_type, source, raw_data, tenant_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          signalId,
          timestamp,
          symbol,
          signalType,
          b.source ?? null,
          typeof b.raw_data === "string"
            ? b.raw_data
            : JSON.stringify(b.raw_data ?? null),
          rowTenant
        )
        .run();
      if (!result.success) {
        throw new Error(result.error || "insert-signal failed");
      }
      return createJsonResponse({ success: true, signal_id: signalId });
    } catch (error) {
      logger.error("rpc/insert-signal failed", { error: toError(error) });
      return Errors.internal(toError(error));
    }
  },
  [requireWriteAuth]
);

/** POST /rpc/insert-system-log — insert a system_logs row */
router.post(
  "/rpc/insert-system-log",
  async (request: Request, env: Env, _ctx: ExecutionContext) => {
    const body = await rpcJsonBody(request);
    if (!body.ok) return body.response;
    const b = body.value;
    const level = String(b.level ?? "INFO");
    const source = String(b.source ?? "unknown");
    const message = String(b.message ?? "");
    if (!message) {
      return Errors.badRequest("Required: message");
    }
    const rowTenant = resolveRowTenant(env, b as { tenantId?: unknown });
    try {
      const result = await prepareValidatedWrite(
        env,
        `INSERT INTO system_logs (level, source, message, details, tenant_id) VALUES (?, ?, ?, ?, ?)`
      )
        .bind(
          level,
          source,
          message,
          typeof b.details === "string"
            ? b.details
            : JSON.stringify(b.details ?? null),
          rowTenant
        )
        .run();
      if (!result.success) {
        throw new Error(result.error || "insert-system-log failed");
      }
      return createJsonResponse({
        success: true,
        changes: result.meta?.changes ?? null,
      });
    } catch (error) {
      logger.error("rpc/insert-system-log failed", { error: toError(error) });
      return Errors.internal(toError(error));
    }
  },
  [requireWriteAuth]
);

// ── Named RPC list (read) endpoints ────────────────────────────────
// Prefer these over free-form /query for trade-worker signal/log reads.
// Fixed SELECT templates + bound limit/offset only (max limit 100).

async function handleListSignals(
  request: Request,
  env: Env
): Promise<Response> {
  // Single body read: pagination + tenantId together (see
  // parseListRpcParamsWithTenant — a second read would see a consumed stream).
  const parsed = await parseListRpcParamsWithTenant(request, 10);
  if (!parsed.ok) return parsed.response;
  const { limit, offset, tenantId } = parsed;
  const rowTenant = resolveRowTenant(env, { tenantId });
  const scope = tenantFilter(rowTenant);
  try {
    const result = await env.DB.prepare(
      `SELECT signal_id, timestamp, symbol, signal_type, source, processed_at
       FROM trade_signals
       WHERE 1 = 1 ${scope.sql}
       ORDER BY processed_at DESC
       LIMIT ? OFFSET ?`
    )
      .bind(...scope.binds, limit, offset)
      .all();
    if (!result.success) {
      throw new Error(result.error || "list-signals failed");
    }
    return createJsonResponse({
      success: true,
      results: result.results || [],
      limit,
      offset,
    });
  } catch (error) {
    logger.error("rpc/list-signals failed", { error: toError(error) });
    return Errors.internal(toError(error));
  }
}

/** GET|POST /rpc/list-signals — recent trade_signals (bound limit/offset) */
router.get("/rpc/list-signals", handleListSignals, [requireReadAuth]);
router.post("/rpc/list-signals", handleListSignals, [requireReadAuth]);

async function handleListSystemLogs(
  request: Request,
  env: Env
): Promise<Response> {
  // Single body read: pagination + tenantId together (see
  // parseListRpcParamsWithTenant — a second read would see a consumed stream).
  const parsed = await parseListRpcParamsWithTenant(request, 20);
  if (!parsed.ok) return parsed.response;
  const { limit, offset, tenantId } = parsed;
  const rowTenant = resolveRowTenant(env, { tenantId });
  const scope = tenantFilter(rowTenant);
  try {
    const result = await env.DB.prepare(
      `SELECT id, timestamp, level, service, message, details
       FROM system_logs
       WHERE 1 = 1 ${scope.sql}
       ORDER BY timestamp DESC
       LIMIT ? OFFSET ?`
    )
      .bind(...scope.binds, limit, offset)
      .all();
    if (!result.success) {
      throw new Error(result.error || "list-system-logs failed");
    }
    return createJsonResponse({
      success: true,
      results: result.results || [],
      limit,
      offset,
    });
  } catch (error) {
    logger.error("rpc/list-system-logs failed", { error: toError(error) });
    return Errors.internal(toError(error));
  }
}

/** GET|POST /rpc/list-system-logs — recent system_logs (bound limit/offset) */
router.get("/rpc/list-system-logs", handleListSystemLogs, [requireReadAuth]);
router.post("/rpc/list-system-logs", handleListSystemLogs, [requireReadAuth]);

/**
 * GET|POST /rpc/list-open-positions — OPEN positions (fixed SQL).
 * Optional exchange filter via query/body `exchange` (alphanumeric + _- only).
 * Prefer this over free-form /query for reconcile / trade-worker fallbacks.
 */
async function handleListOpenPositions(
  request: Request,
  env: Env
): Promise<Response> {
  let exchange: string | undefined;
  let filterTenant: unknown;
  try {
    if (request.method === "GET") {
      const params = new URL(request.url).searchParams;
      const ex = params.get("exchange");
      if (ex != null && ex.trim() !== "") exchange = ex.trim();
      filterTenant = params.get("tenantId");
    } else {
      const body = (await request.json().catch(() => null)) as {
        exchange?: unknown;
        tenantId?: unknown;
      } | null;
      if (body && typeof body.exchange === "string" && body.exchange.trim()) {
        exchange = body.exchange.trim();
      }
      filterTenant = body?.tenantId;
    }
  } catch {
    return Errors.badRequest("Invalid request for list-open-positions");
  }

  if (exchange !== undefined) {
    // Reject injection-ish tokens; exchanges are short identifiers.
    if (
      exchange.length > 32 ||
      !/^[A-Za-z0-9_-]+$/.test(exchange) ||
      exchange.includes("__proto__")
    ) {
      return Errors.badRequest("Invalid exchange filter");
    }
  }

  const rowTenant = resolveRowTenant(env, { tenantId: filterTenant });
  const scope = tenantFilter(rowTenant);

  try {
    if (exchange) {
      const result = await env.DB.prepare(
        `SELECT id, exchange, symbol, side, size, status, updated_at
         FROM positions
         WHERE status = 'OPEN' AND exchange = ? ${scope.sql}
         ORDER BY updated_at DESC`
      )
        .bind(exchange, ...scope.binds)
        .all();
      if (!result.success) {
        throw new Error(result.error || "list-open-positions failed");
      }
      return createJsonResponse({
        success: true,
        results: result.results || [],
        positions: result.results || [],
        exchange,
      });
    }

    const result = await env.DB.prepare(
      `SELECT id, exchange, symbol, side, size, status, updated_at
       FROM positions
       WHERE status = 'OPEN' ${scope.sql}
       ORDER BY updated_at DESC`
    )
      .bind(...scope.binds)
      .all();
    if (!result.success) {
      throw new Error(result.error || "list-open-positions failed");
    }
    return createJsonResponse({
      success: true,
      results: result.results || [],
      positions: result.results || [],
    });
  } catch (error) {
    logger.error("rpc/list-open-positions failed", { error: toError(error) });
    return Errors.internal(toError(error));
  }
}

router.get("/rpc/list-open-positions", handleListOpenPositions, [
  requireReadAuth,
]);
router.post("/rpc/list-open-positions", handleListOpenPositions, [
  requireReadAuth,
]);

export default {
  fetch: withRequestLog(
    async (
      request: Request,
      env: Env,
      ctx: ExecutionContext
    ): Promise<Response> => {
      const cors = corsHeaders(resolveCorsOptions(request, env));
      const corsHeadersOrEmpty =
        Object.keys(cors).length > 0 ? cors : internalCorsHeaders();
      if (request.method === "OPTIONS") {
        return wrapWithSecurityHeaders(
          new Response(null, { status: 204, headers: corsHeadersOrEmpty })
        );
      }
      try {
        // Idempotent per-isolate migration for row-level tenant isolation.
        await ensureTenantSchema(env.DB);
        const response = await router.handle(request, env, ctx);
        const wrapped = new Response(response.body, response);
        for (const [key, value] of Object.entries(corsHeadersOrEmpty)) {
          wrapped.headers.set(key, value);
        }
        return wrapWithSecurityHeaders(wrapped);
      } catch (error) {
        logger.error("Unhandled router error", { error: toError(error) });
        return wrapWithSecurityHeaders(Errors.internal(toError(error)));
      }
    },
    { service: "d1-worker", module: "router" }
  ),
};

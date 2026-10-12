/**
 * Copyright (c) 2026 HOOX · HOOX · jango-blockchained (hoox-sh)
 * SPDX-License-Identifier: Apache-2.0
 */

import type { D1Database } from "@cloudflare/workers-types";
import { toError } from "@hoox-sh/hoox-shared/errors";

export interface DashboardStats {
  totalTrades: number;
  winRate: number;
  totalPnlUSDT: number;
  activePositionsCount: number;
  dailyTradesCount: number;
}

export async function computeDashboardStats(
  db: D1Database,
  /** Tenant scope; undefined = unscoped self-host rows. */
  tenantId?: string
): Promise<{ stats: DashboardStats } | { error: string }> {
  try {
    const now = Math.floor(Date.now() / 1000);
    const todayStart = now - (now % 86400);

    // Optional tenant predicate spliced into every aggregate. The column is
    // bound (never interpolated) and empty-scope keeps the original SQL.
    const tSql = tenantId ? "AND tenant_id = ?" : "";
    const tBinds = tenantId ? [tenantId] : [];

    // Independent aggregates — single DB.batch() round-trip.
    // Exclude testnet fills (status TEST_EXECUTED) and namespaced test positions
    // (`%-testnet-%` ids) so dashboard headlines reflect live exposure only.
    const stmts = [
      db
        .prepare(
          `SELECT COUNT(*) as count FROM trades WHERE (status IS NULL OR status != 'TEST_EXECUTED') ${tSql}`
        )
        .bind(...tBinds),
      db
        .prepare(
          `SELECT COUNT(*) as count FROM positions WHERE status = 'OPEN' AND id NOT LIKE '%-testnet-%' ${tSql}`
        )
        .bind(...tBinds),
      db
        .prepare(
          `SELECT COUNT(*) as count FROM positions WHERE status = 'CLOSED' AND id NOT LIKE '%-testnet-%' ${tSql}`
        )
        .bind(...tBinds),
      db
        .prepare(
          `SELECT COUNT(*) as count FROM positions WHERE status = 'CLOSED' AND id NOT LIKE '%-testnet-%' AND unrealized_pnl > 0 ${tSql}`
        )
        .bind(...tBinds),
      db
        .prepare(
          `SELECT COUNT(*) as count FROM trades WHERE timestamp >= ? AND (status IS NULL OR status != 'TEST_EXECUTED') ${tSql}`
        )
        .bind(todayStart, ...tBinds),
      // Live total PnL: sum closed realized/unrealized_pnl + open unrealized_pnl
      db
        .prepare(
          `SELECT COALESCE(SUM(unrealized_pnl), 0) as total FROM positions WHERE id NOT LIKE '%-testnet-%' ${tSql}`
        )
        .bind(...tBinds),
    ];

    const [
      totalRow,
      activePosRow,
      totalClosedRow,
      profitableRow,
      dailyRow,
      pnlRow,
    ] = await db.batch(stmts);

    // db.batch returns D1Result[] — each .results array contains the rows
    const totalTrades =
      (totalRow?.results?.[0] as { count: number } | undefined)?.count ?? 0;
    const activePositionsCount =
      (activePosRow?.results?.[0] as { count: number } | undefined)?.count ?? 0;
    const dailyTradesCount =
      (dailyRow?.results?.[0] as { count: number } | undefined)?.count ?? 0;

    const closedCount =
      (totalClosedRow?.results?.[0] as { count: number } | undefined)?.count ??
      0;
    const profitCount =
      (profitableRow?.results?.[0] as { count: number } | undefined)?.count ??
      0;

    const totalPnlUSDT = Number(
      (pnlRow?.results?.[0] as { total: number } | undefined)?.total ?? 0
    );

    let winRate = 0;
    if (closedCount > 0) {
      winRate = Math.round((profitCount / closedCount) * 100 * 10) / 10;
    }

    return {
      stats: {
        totalTrades,
        winRate,
        totalPnlUSDT: Number.isFinite(totalPnlUSDT) ? totalPnlUSDT : 0,
        activePositionsCount,
        dailyTradesCount,
      },
    };
  } catch (error) {
    return { error: toError(error) };
  }
}

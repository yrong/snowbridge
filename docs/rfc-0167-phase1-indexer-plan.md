# RFC-0167 Circuit Breaker — Phase 1 (Indexer) Implementation Plan

Target repo: **snowbridge-subsquid** (`@subsquid/graphql-server` + TypeORM + type-graphql, Postgres).
This plan is the offchain **detection** half of the circuit breaker: compute per-asset net
flow over a rolling window and the 7-day baseline, and expose both via GraphQL so
`operations/monitor.ts` (Phase 3) can apply caps and alarm. **No enforcement here.**

## Key facts discovered (ground truth)

- Custom resolvers live in `src/server-extension/resolvers/index.ts` and are re-exported from
  `src/server-extension/resolvers.ts`. `squid-graphql-server` auto-discovers them (type-graphql).
  **No `schema.graphql` change is needed for resolvers** — they are code, not `@entity` types.
- Both relevant entities already carry everything we need:
  - `TransferStatusToEthereumV2` (P→E, the **outflow / draining** direction)
  - `TransferStatusToPolkadotV2` (E→P, the **inflow** direction)
  - Fields on both: `tokenAddress: String`, `amount: BigInt`, `amountUSDC: BigInt`,
    `status: Int` (1 = completed), `timestamp: DateTime @index`, `fromV1: Boolean`.
- Table names (snake_case): `transfer_status_to_ethereum_v2`, `transfer_status_to_polkadot_v2`.
- `amount` is a wei-scale `BigInt` → **must be returned as `String`** (cast `::text`) to avoid
  JS Number precision loss. Existing resolvers return `Number` only for second-scale `elapse` values.
- **`tokenAddress` is NOT indexed today** (only `timestamp`, `status`, `messageId`, `txHash`,
  `nonce`, `blockNumber` are). Grouping by it over a time window needs an index (see Step 4).
- `amountUSDC` exists → a USD-denominated variant is *possible* later, but the RFC mandates
  per-asset native-unit denomination with no oracle dependency, so **native `amount` is primary**.

## Net flow definition

Per `tokenAddress`, over a trailing window, counting only completed (`status = 1`) transfers:

```
outflow(asset) = Σ amount of P→E transfers   (transfer_status_to_ethereum_v2)
inflow(asset)  = Σ amount of E→P transfers   (transfer_status_to_polkadot_v2)
netFlow(asset) = outflow − inflow            (positive = net drain toward Ethereum)
```

Decisions baked in (flag for review):
- **Include `from_v1` transfers.** They are real flows. (The nonce resolvers exclude them because
  v1 nonces are a separate sequence — not relevant to value accounting.)
- **Group by `token_address`.** PNAs identified only by `tokenLocation` will land in the
  `NULL` bucket and are filtered out (`token_address is not null`). Acceptable for v1 since the
  RFC scopes to the Ethereum Gateway track (ERC20/Ether). Revisit if PNA coverage is required.
- **Median over active hours only** (hours with zero transfers don't appear). This makes the
  baseline reflect typical *active* throughput; documented as a tuning choice.

---

## Step 1 — Add the resolver classes

File: `src/server-extension/resolvers/index.ts`. Add a positive-int validator and two
`@ObjectType`s + one `@Resolver`, mirroring the existing `TransferElapseResolver` style
(constructor takes `private tx: () => Promise<EntityManager>`).

```ts
function validatePositiveInt(value: number, name: string): void {
    if (!Number.isInteger(value) || value <= 0) {
        throw new Error(`Invalid ${name} parameter: must be a positive integer`)
    }
}

@ObjectType()
export class AssetNetFlowResult {
    @Field(() => String, { nullable: false })
    tokenAddress!: string
    @Field(() => String, { nullable: false })
    outflow!: string // Σ P→E amount, native units, as decimal string
    @Field(() => String, { nullable: false })
    inflow!: string // Σ E→P amount
    @Field(() => String, { nullable: false })
    netFlow!: string // outflow − inflow (may be negative)
    @Field(() => Number, { nullable: false })
    transferCount!: number
}

@ObjectType()
export class AssetFlowBaselineResult {
    @Field(() => String, { nullable: false })
    tokenAddress!: string
    @Field(() => String, { nullable: false })
    medianHourlyNetFlow!: string // percentile_cont(0.5) of hourly net flow, as string
    @Field(() => Number, { nullable: false })
    sampleHours!: number // number of active hourly buckets the median is drawn from
}

@Resolver()
export class AssetVelocityResolver {
    constructor(private tx: () => Promise<EntityManager>) {}

    // Per-asset net flow over a rolling window (default 24h), completed transfers only.
    @Query(() => [AssetNetFlowResult])
    async assetNetFlow(
        @Arg("windowHours", { nullable: true, defaultValue: 24 })
        windowHours: number
    ): Promise<AssetNetFlowResult[]> {
        validatePositiveInt(windowHours, "windowHours")
        const manager = await this.tx()
        const query = `
            with outbound as (
                select token_address, coalesce(sum(amount), 0) as amt, count(*) as cnt
                from transfer_status_to_ethereum_v2
                where status = 1 and token_address is not null
                  and timestamp > now() - ($1 || ' hours')::interval
                group by token_address
            ),
            inbound as (
                select token_address, coalesce(sum(amount), 0) as amt, count(*) as cnt
                from transfer_status_to_polkadot_v2
                where status = 1 and token_address is not null
                  and timestamp > now() - ($1 || ' hours')::interval
                group by token_address
            )
            select
                coalesce(o.token_address, i.token_address) as "tokenAddress",
                coalesce(o.amt, 0)::text as outflow,
                coalesce(i.amt, 0)::text as inflow,
                (coalesce(o.amt, 0) - coalesce(i.amt, 0))::text as "netFlow",
                (coalesce(o.cnt, 0) + coalesce(i.cnt, 0))::int as "transferCount"
            from outbound o
            full outer join inbound i on o.token_address = i.token_address
        `
        return manager.query(query, [windowHours])
    }

    // Trailing 7-day median of per-hour net flow per asset (cap-formula denominator).
    @Query(() => [AssetFlowBaselineResult])
    async assetFlowBaseline(
        @Arg("windowDays", { nullable: true, defaultValue: 7 })
        windowDays: number
    ): Promise<AssetFlowBaselineResult[]> {
        validatePositiveInt(windowDays, "windowDays")
        const manager = await this.tx()
        const query = `
            with buckets as (
                select token_address, date_trunc('hour', timestamp) as hr, sum(amount) as amt
                from transfer_status_to_ethereum_v2
                where status = 1 and token_address is not null
                  and timestamp > now() - ($1 || ' days')::interval
                group by token_address, hr
                union all
                select token_address, date_trunc('hour', timestamp) as hr, -sum(amount) as amt
                from transfer_status_to_polkadot_v2
                where status = 1 and token_address is not null
                  and timestamp > now() - ($1 || ' days')::interval
                group by token_address, hr
            ),
            hourly as (
                select token_address, hr, sum(amt) as net
                from buckets group by token_address, hr
            )
            select
                token_address as "tokenAddress",
                (percentile_cont(0.5) within group (order by net))::text as "medianHourlyNetFlow",
                count(*)::int as "sampleHours"
            from hourly
            group by token_address
        `
        return manager.query(query, [windowDays])
    }
}
```

Notes:
- `($1 || ' hours')::interval` builds the interval safely from the bound parameter; the value is
  also validated as a positive integer, so there is no injection surface.
- Column aliases are double-quoted to preserve camelCase so rows map straight onto the `@ObjectType`.

## Step 2 — Re-export the new classes

File: `src/server-extension/resolvers.ts` — add to the existing export block:

```ts
export {
    AssetNetFlowResult,
    AssetFlowBaselineResult,
    AssetVelocityResolver,
    // ...existing exports
} from "./resolvers/index"
```

## Step 3 — (No schema.graphql entity change)

Custom resolvers are not `@entity` types, so `schema.graphql` and `src/model` are untouched.
The GraphQL SDL for `assetNetFlow` / `assetFlowBaseline` is generated by type-graphql at serve time.

## Step 4 — Add indexes for the grouping (performance)

These queries scan a time window and `GROUP BY token_address`. With `tokenAddress` unindexed,
expect sequential scans that worsen as tables grow. Two options:

- **Preferred — schema annotation + codegen migration.** Add `@index` to `tokenAddress` on both
  entities in `schema.graphql`, then regenerate:
  ```
  npx squid-typeorm-codegen
  npx squid-typeorm-migration generate
  ```
  Even better is a composite index `(tokenAddress, timestamp)`; if codegen only emits single-column
  indexes, hand-edit the generated migration to:
  ```sql
  CREATE INDEX "idx_te_v2_token_ts" ON "transfer_status_to_ethereum_v2" ("token_address", "timestamp");
  CREATE INDEX "idx_tp_v2_token_ts" ON "transfer_status_to_polkadot_v2" ("token_address", "timestamp");
  ```
- **Alternative — manual migration only** in `db/migrations/` with the two `CREATE INDEX`
  statements above (and matching `DROP INDEX` in `down`).

Run `npx squid-typeorm-migration apply` against the DB. Verify with `EXPLAIN ANALYZE` that the
window aggregation uses the index.

## Step 5 — Build & smoke test

```
npm run build           # or: npx tsc
npm run serve           # squid-graphql-server (local)
```

Query checks (point at local graphql endpoint):

```bash
curl -s -H 'Content-Type: application/json' -X POST \
  -d '{"query":"query { assetNetFlow(windowHours: 24) { tokenAddress outflow inflow netFlow transferCount } }"}' \
  http://localhost:4350/graphql | jq .

curl -s -H 'Content-Type: application/json' -X POST \
  -d '{"query":"query { assetFlowBaseline(windowDays: 7) { tokenAddress medianHourlyNetFlow sampleHours } }"}' \
  http://localhost:4350/graphql | jq .
```

Acceptance criteria:
- `assetNetFlow` returns one row per active token; `netFlow == outflow − inflow` (verify with a
  manual `SUM` for one token); tokens active only on one side still appear (FULL OUTER JOIN).
- `assetFlowBaseline` returns a numeric median per token with `sampleHours > 0`; tokens with a
  single active hour return that hour's net as the median.
- Large wei amounts come back as exact decimal **strings** (no `e+` / precision loss).
- `windowHours = 0` / negative / non-integer → GraphQL error from `validatePositiveInt`.
- `EXPLAIN ANALYZE` shows index usage after Step 4; both queries return well under the monitor's
  scan budget on production data volume.

## Out of scope for Phase 1 (handled later)

- API fetchers `fetchAssetNetFlow` / `fetchAssetFlowBaseline` in `web/packages/api` (Phase 2).
- Cap evaluation `cap = max(multiplier × medianHourlyNetFlow × windowHours, floor)`, CloudWatch
  metrics, and `AssetVelocityCapBreached` alarm in `web/packages/operations` (Phase 3).
- Onchain enforcement / locking (the RFC itself).
- Optional USD-denominated variant using `amountUSDC` (cross-asset view; not RFC-required).

## Open questions to confirm before/while implementing

1. Include or exclude `from_v1` transfers in flow totals? (Plan: include.)
2. PNA assets keyed by `tokenLocation` — needed in v1, or defer? (Plan: defer; ERC20/Ether only.)
3. Baseline median over active hours only, or zero-fill idle hours via `generate_series`?
   (Plan: active hours only; revisit if it inflates caps for bursty assets.)
4. Should `assetNetFlow` accept an optional `tokenAddress` filter arg for targeted queries?
   (Cheap to add; useful for the monitor's per-asset alarm path.)
</content>
</invoke>

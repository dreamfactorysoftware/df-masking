# Changelog

All notable changes to `dreamfactory/df-masking` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning.

## [0.1.0] - 2026-11-18

First release, shipped with DreamFactory 7.8.0. Commercial (Gold). Requires DreamFactory 7.8 or
later 7.x.

### Added
- Data Masking: deterministic column classification (names, validated value samples, table
  context) for every df-sqldb-family service, with masked / review / clear verdicts, evidence and
  masked examples. Raw values never leave memory. Rule pack 2026.11.1.
- Response masking (mode Off / Preview / On) for covered services, including related records,
  ahead of event scripts, caching and logging; request guards for filters, ordering, grouping,
  functions, write-back, inserts and error text; AI/MCP sessions masked by default and blocked from
  uncovered database services when On.
- 23 classes in 4 tiers with formats redact, last4, initial, year, token (per-instance HMAC),
  null and span. Virtual fields and SELECT `db_function` fields inherit the masking of the columns
  their expression reads.
- Response headers in mode On: `X-DreamFactory-Masked-Fields` lists the masked fields
  (`relation.field` for related records) and `X-DreamFactory-Masking-Rewrites` lists the filter,
  order, group and field items Data Masking rewrote. Headers report what happened and never control
  masking; Preview records its impact in Activity instead.
- Real-value access: admins (none / selected with expiring grants / all), roles (all or all
  except restricted), AI sessions (masked / same as admins); loosening, and lowering the mode from
  On, reserved to the super admin (the df-compliance root admin when one is designated).
- Custom detection rules (column name and value patterns) with live testing. Adding a value rule
  re-scans the covered databases so the rule applies right away (`scan_started` in the response);
  each rule reports how many columns it matched.
- Compliance baselines: HIPAA, PCI DSS v4.0.1, GLBA (FTC Safeguards Rule and the Interagency
  Guidelines), CJIS (Security Policy v6.1), GDPR, SOC 2 (2017 TSC, 2022 points of focus) and
  ISO/IEC 27001:2022 presets, live checklists mapped to framework references, and JSON/CSV evidence
  reports that carry the frameworks and a "not a certification" disclaimer.
- System resources `data_masking` and `security_baseline` (Gold, full system admins only), masking
  activity log, and `php artisan df:masking` (status, scan, mode, grant, revoke, baseline, setup).
  Without those resources (package not installed) the admin app's Data Masking and Compliance pages
  show DreamFactory's standard paywall on every license, Gold included.
- License level: the settings API, the baselines API and `php artisan df:masking` need a Gold
  license level, as df-compliance's service reports do (403 "Data Masking is not available for your
  license. Please upgrade to Gold."). On other levels the command keeps `status`, `help`, `revoke`
  and `mode off`, service changes start no background scan, and masking already turned on keeps
  applying.
- The first scan that finds columns switches the mode Off -> Preview (no data changes) when no mode
  was chosen yet.
- Background scans: a covered service is scanned as soon as it is created or changed (once any
  scan has run or the mode is not Off); tables and columns seen between scans are classified by name
  at once, span-masked in mode On when they hold text, and start a scan of their service at once (at
  most once per service per minute, deferred rather than dropped).
- Configuration through `DF_MASKING_*` environment variables (token key, activity retention, rule
  test budget, scan timeouts, access cache, PHP binary for detached scans).
- Additive migrations for the `dm_*` tables, portable across MySQL/MariaDB, PostgreSQL, SQL Server
  and SQLite system databases.
- `tests/Live`: end-to-end suites for a running instance (enforcement, filters, cleanup,
  baselines, performance, byte-for-byte existing-instance diff, stored-value check), for MySQL,
  PostgreSQL, SQL Server and SQLite system databases.

### Unchanged behavior
- Installing the package changes nothing on its own: with mode Off, API responses are
  byte-for-byte identical to an instance without the package.

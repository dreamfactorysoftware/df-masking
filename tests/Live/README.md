# df-masking live suites

These scripts check Data Masking and Compliance baselines against a **running** DreamFactory 7.8
Gold instance with df-masking installed. They are not part of `bin/test.sh`: the PHPUnit suites
in `tests/Unit` need no running stack, these do. Python 3.8+ (standard library only) and the
`docker` CLI (for direct database reads) are required. Use a test instance with synthetic data
only: transcripts include API responses.

Each suite changes masking settings (mode, access, formats, service cache, temporary services,
event scripts, agents, a temporary column) and restores what it changed in `finally`.

| Script | Proves |
|---|---|
| `enforcement.py [check...]` | Formats in JSON/XML/CSV, related and single records, the filter/order/group/fields matrix, write-back and expressions, error scrubbing, event scripts and `platform.api`, `_spec` models, preview, admin grants and AI sessions, role scopes, uncovered services, service cache, `_proc`/`_func`, the MCP daemon, df-agents, never-scanned columns, zero queries when off, request headers that must change nothing. Checks: `formats related filters writes errors script platform_api spec preview access ai_settings uncovered cache proc mcp agents unscanned queries ignored_headers` (or `all`). `unscanned` (evidence `17-unscanned-column-inline`) checks that in mode On, a column added after the scan whose name says nothing but that holds emails is masked on its first request, and a scan of its service starts within 5 s. `ignored_headers` (evidence `20-ignored-request-headers`) sends `X-DreamFactory-Masking: off`, `X-DreamFactory-Masking-View: real` or `masked`, `X-DreamFactory-Masked-Fields` and `X-DreamFactory-Masking-Rewrites` with an app API key and checks that status, body and masking headers equal the baseline. |
| `filters.py` | Extra filter probes, as the role user in mode On: a comparison the caller may not make on a masked column matches no rows (count 0, `X-DreamFactory-Masking-Rewrites: filter:<column>`), `OR` with a masked operand keeps the clear side (the IL count), and allowed comparisons (identity `=`/`IN`, `IS NOT NULL`, quasi `=`) count as without masking. Also `contains`, `starts with`, ranges, `NOT` groups, upper-case names, `between`, sort and group, related `.order`/`.fields`, `include_count`, and `filter[]` (which DreamFactory ignores; reported as INFO, and Data Masking adds no `X-DreamFactory-Masking-Rewrites` item for it). |
| `cleanup.py` | Deleting a role or an admin removes its df-masking rows. |
| `baselines.py` | Every baseline evaluates; Apply `hipaa` and `pci_dss` (with `mode: on`) change exactly the settings `changes` listed, read back from the API; second Apply changes nothing; JSON/CSV reports contain none of the raw values. |
| `perf.py` | Enforcement overhead on a 100-row GET, off vs preview vs on (p50 of 100 requests per mode, budget 10 ms). |
| `existing_instance.py record\|diff` | Byte-for-byte API responses before and after installing the package (run `record` before `bin/dev-install.sh`, again after, then `diff`). |
| `valuecheck.php` | Runs inside the web container: re-samples every covered service with the scanner's Sampler and searches every `dm_*` row and `storage/logs` for the sampled values. Exit 0 = none found, 3 = found (prints hashes, never values). SQLite services whose database file does not exist are skipped before any connection is opened, so the instance is left as found. |

```bash
tests/Live/run.sh all                      # everything above except existing_instance.py
tests/Live/run.sh enforcement formats spec # selected enforcement checks
tests/Live/run.sh perf
tests/Live/run.sh values
```

## Expected fixtures

Provide:

- SQL services `crm` (PostgreSQL, the classifier corpus with table `CustomerContacts`), `crm_mysql`
  (MySQL: `customers` with a UNIQUE `email`, `payment_methods`, `orders` with a `customers_by_customer_id`
  relation, ...), `store` and `legacy` for `existing_instance.py`;
- a role (`DM_ROLE`, default `support`) with GET on `crm/_table/*` and `crm_mysql/_table/*`, and an app with that role
  (`DM_API_KEY`);
- the df-compliance root admin (`DM_ADMIN_EMAIL`/`DM_ADMIN_PASSWORD`) and a second admin (`DM_ADMIN2_*`);
- an MCP service bound to `crm` with API key auth (`DM_MCP_URL`, default `http://127.0.0.1/mcp/crm_mcp`);
- a first scan that found columns (mode Preview).

`perf.py` and `cleanup.py` need only `crm_mysql`, the role and app, and the two admins.

| Variable | Default |
|---|---|
| `DM_BASE_URL` | required, for example `http://127.0.0.1/api/v2/` |
| `DM_ADMIN_EMAIL`, `DM_ADMIN_PASSWORD` | required: the root admin |
| `DM_ADMIN2_EMAIL`, `DM_ADMIN2_PASSWORD` | required: a second admin |
| `DM_API_KEY` | required: the key of an app with role `DM_ROLE` |
| `DM_ROLE` | `support` |
| `DM_MYSQL` | required: any command prefix that runs the mysql client against the server holding `crm_mysql`, for example `docker exec -e MYSQL_PWD <mysql container> mysql -uroot` |
| `DM_SYSDB` | `DM_MYSQL` + `dreamfactory`: the system database's client command prefix, ending with what selects the database (see below) |
| `DM_SYSDB_DIALECT` | `mysql`; or `pgsql`, `sqlsrv`, `sqlite` |
| `DM_PG` | none: a psql command prefix for the PostgreSQL corpus DB, for example `docker exec <pg container> psql -U postgres -d corpus` (read-only use) |
| `DM_DOCKER`, `DM_WEB_CONTAINER` | `sudo -n docker`; the web container is required by `run.sh values` |
| `DM_MCP_URL`, `DM_MCP_HOST` | `http://127.0.0.1/mcp/crm_mcp`, `localhost` |
| `DM_EVIDENCE_DIR` | `$TMPDIR/df-masking-live` |

## System database other than MySQL

The suites read and update `dm_*` rows directly. When the DreamFactory system database is not MySQL,
set `DM_SYSDB` and `DM_SYSDB_DIALECT`:

```bash
# PostgreSQL
DM_SYSDB='sudo -n docker exec <pg container> psql -U postgres -d <system db>' DM_SYSDB_DIALECT=pgsql
# SQL Server
DM_SYSDB='sudo -n docker exec <mssql container> /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P <password> -d <system db>' DM_SYSDB_DIALECT=sqlsrv
# SQLite: the exec prefix into the web container, then the database file (PHP's PDO runs the query,
# so the container needs no sqlite3 client)
DM_SYSDB='sudo -n docker exec <web container> /opt/dreamfactory/storage/databases/<file>.sqlite' DM_SYSDB_DIALECT=sqlite
```

`DM_MYSQL` is then needed only for the `crm_mysql` data database.

## Running against your own throwaway stack

Point the variables at it, for example:

```bash
export DM_BASE_URL=http://127.0.0.1:8795/api/v2/ \
  DM_ADMIN_EMAIL=... DM_ADMIN_PASSWORD=... DM_ADMIN2_EMAIL=... DM_ADMIN2_PASSWORD=... \
  DM_API_KEY=<app key> DM_MYSQL='sudo -n docker exec -e MYSQL_PWD <mysql container> mysql -uroot' \
  DM_WEB_CONTAINER=<web container> DM_EVIDENCE_DIR=$PWD/live-evidence
tests/Live/run.sh perf
tests/Live/run.sh cleanup
```

To reach a database that runs in another compose project (for example a shared SQL Server), attach
**that database container** to your stack's network. Never `docker network connect` your DreamFactory
web container to another project's network: that project's `mysql` and `redis` service names then
resolve to its containers, and your web container silently uses the other stack's system database
and cache.

## Notes

- `enforcement.py access` restores the access settings it found, re-sending existing grants without a
  duration. If one of those grants expires during the run, the restore gets 409 (logged as `restore
  failed`) instead of re-creating the grant. That is intended.
- `perf.py` timings are client-side wall time and vary with host load; compare modes within one run.
  On a shared host, On minus Off varied from 5 to 11 ms between five consecutive runs of the same
  code, so `perf.py` can fail its 10 ms budget on a busy host. Run it several times.
- `enforcement.py unscanned` adds columns to `crm_mysql.customers` and drops them in `finally`.
- The opt-in unit test `tests/Unit/Scanner/SystemDbPortabilityTest.php` (`DM_SYSDB_URLS`, see the
  package README) also runs the `dm_scan.scope` migration up, down and up again on each database.

# df-masking: Data Masking and Compliance baselines for DreamFactory

`dreamfactory/df-masking` is a commercial (Gold) DreamFactory package with two features:

- **Data Masking** finds the sensitive columns in your SQL databases and masks their values in API
  responses. Apps, roles and AI/MCP tools get masked values. So do admins, until someone gives them
  access.
- **Compliance baselines** give you presets, live checklists and evidence exports for HIPAA,
  PCI DSS, GLBA, CJIS, GDPR, SOC 2 and ISO 27001. A baseline covers only the settings DreamFactory
  owns. It is not a certification.

The screens are in the admin app under **Security > Data Masking** and **Security > Compliance**
(in the command palette, Ctrl/Cmd-K, typing `pii`, `pci`, `phi` or `mask` lists Data Masking first).
On an instance without this package, those pages show DreamFactory's standard paywall on every
license (Gold included), like Rate Limiting, Scheduler and Reporting when their resource is missing.
This package is the backend: the classifier, the scanner, enforcement, the `system/data_masking` and
`system/security_baseline` APIs, and `php artisan df:masking`.

Installing the package changes nothing on its own: API responses stay byte-for-byte identical.
Masking starts **Off**. The first scan that finds columns moves it to **Preview**, unless someone
already chose a mode. Preview changes no response: the Activity tab records which callers would get
masked values, and from which tables. Values are masked only after an admin turns masking **On**, and
On is refused until a scan has found columns.

## Requirements

| | |
|---|---|
| DreamFactory | 7.8 or later 7.x, **Gold**. The package requires `dreamfactory/df-core ~1.0.4` and `dreamfactory/df-system ~0.6.2`. |
| License | `dreamfactory/df-masking` is distributed with the DreamFactory Gold package and is licensed under the DreamFactory Terms of Use ([LICENSE](LICENSE)); it is not licensed for other tiers. The instance's license level must be Gold: on other levels `system/data_masking` and `system/security_baseline` answer 403 ("Data Masking is not available for your license. Please upgrade to Gold."), `df:masking` keeps only `status`, `help`, `revoke` and `mode off`, and service changes start no background scan. Masking already turned on keeps applying. |
| PHP | 8.3 or later with `json` and `mbstring` (the DreamFactory images have both). |
| Databases | SQL services from `dreamfactory/df-sqldb` and its connectors (MySQL/MariaDB, PostgreSQL, SQL Server, SQLite, Oracle, Snowflake and others) are the covered service types. |
| System database | MySQL/MariaDB, PostgreSQL, SQL Server or SQLite (see [System databases](#system-databases)). |
| Cache | Any Laravel cache store for one node; several nodes need one shared store (see [Several DreamFactory nodes](#several-dreamfactory-nodes)). |
| Optional | `dreamfactory/df-compliance` (root admin), `dreamfactory/df-limits` and `dreamfactory/df-logger` (checked by the Compliance baselines). |

---

## Quickstart

From nothing to masking On takes a few minutes.

### 1. Install the package

Skip this step if your Gold build already includes `dreamfactory/df-masking`. Otherwise add the
package's GitHub repository and require it:

```bash
cd /opt/dreamfactory
composer config repositories.df-masking vcs https://github.com/dreamfactorysoftware/df-masking
composer require "dreamfactory/df-masking:~0.1.0" --update-no-dev
```

### 2. Scan your databases

Data Masking scans the SQL databases you have added as DreamFactory services.

- **Existing install** (your databases are already services): run one command, or open
  **Security > Data Masking** and click **Scan databases**. `setup` creates the tables, scans every
  SQL service, and applies a baseline if you name one:

  ```bash
  php artisan df:masking setup                    # or: setup --baseline=hipaa
  ```

  `--baseline` takes `hipaa`, `pci_dss`, `glba`, `cjis`, `gdpr`, `soc2` or `iso27001`.
- **New install:** a default install has only the empty built-in `db`, so there is nothing to scan
  yet. Add your SQL databases as services first, then run `setup`. If you run `setup` before that, it
  ends with `Next: add a SQL database service, then run php artisan df:masking scan.` Once a scan has
  run (or the mode is Preview or On), each database service you add is scanned as soon as you create
  it.

A typical database takes a few seconds. When the first scan that finds columns finishes, the mode is
**Preview**.

### 3. Review, then turn masking On

1. In **Data Masking > Columns**, open **To review**. For each column pick **Keep masked**, **Not
   sensitive** or another class. Columns waiting for review are masked once masking is On.
2. Switch the mode to **On**, or run `php artisan df:masking mode on`.
3. Check: `php artisan df:masking status` prints `Mode: On` and the column counts.

Before you turn masking On for existing apps, read [What changes for apps in mode On](#what-changes-for-apps-in-mode-on).

### Docker

Run the commands inside the container as the web user:

```bash
docker exec -u www-data <container> php /opt/dreamfactory/artisan df:masking setup
docker exec -u www-data <container> php /opt/dreamfactory/artisan df:masking status
```

**Make the install survive container re-creation.** A package installed with `composer require`
inside a running container lives in that container's writable layer. Pulling a new image, or
re-creating the container for any other reason, removes it. The Data Masking settings survive in the
system database, but nothing enforces them, so apps get real values again and nothing warns you. Bake
the package into your image instead:

```dockerfile
FROM <your DreamFactory Gold image>
RUN cd /opt/dreamfactory && composer require dreamfactory/df-masking --no-interaction
```

After every deploy, `php artisan df:masking status` should exit 0. It exits 1 when the package or its
tables are missing, so you can use it in a deploy check or a container health check.

### Several DreamFactory nodes

All nodes must share one cache store (for example `CACHE_DRIVER=redis` or `memcached`). Data Masking
keeps its settings and table policies in the cache for up to an hour, under a version number that
every change bumps in that cache. With a per-node cache (`file`, `apc`), a change made through one
node does not reach the others: in a test with two nodes on one system database, after masking was
turned On through the Redis node, the node with a `file` cache kept serving real values until
`php artisan cache:clear` ran on it.

### Upgrading

Run `php artisan df:masking setup` again (or `php artisan migrate --force`, then a scan). `setup`
applies the package's pending migrations ("Updating Data Masking tables..."), re-scans, and is safe to
re-run on a live instance: `--mode` only ever raises the mode, and otherwise prints
`Masking is already On; leaving it On (use df:masking mode preview to lower it).`

The package's migrations are additive and portable across MySQL/MariaDB, PostgreSQL, SQL Server and
SQLite system databases.

### Turning it off, removing it

`php artisan df:masking mode off` (or the switch in the admin app) makes the package a no-op:
responses are byte-for-byte those of an instance without it, even with scan results stored.

To remove the package and its tables:

```bash
cd /opt/dreamfactory
php artisan migrate:reset --path=vendor/dreamfactory/df-masking/database/migrations --force
composer remove dreamfactory/df-masking
php artisan cache:clear
```

`migrate:reset --path` rolls back only this package's five migrations. It drops the nine `dm_*`
tables and removes the five rows from `migrations`. It lists DreamFactory's other migrations as
"Migration not found" and leaves them alone. If you already removed the package, drop the tables
(`dm_setting`, `dm_column`, `dm_mask_format`, `dm_rule`, `dm_admin_grant`, `dm_role_access`,
`dm_activity`, `dm_scan`, `dm_baseline`) and delete the five rows by exact name:

```sql
DELETE FROM migrations WHERE migration IN ('2026_10_29_000001_create_dm_tables',
  '2026_10_29_000003_dm_exact_names_and_scan_failures', '2026_10_29_000004_dm_scan_scope',
  '2026_10_29_000005_dm_scan_read_services', '2026_10_29_000100_create_dm_baseline_table');
```

Then run `php artisan cache:clear`. Leaving a row behind makes a later reinstall skip that
migration. Do not use a `LIKE` pattern: `'%_dm_%'` also matches df-compliance's
`2019_04_01_142947_add_is_root_admin_to_user`. The package's migrations drop its cached settings
themselves when they create or drop the tables, so a reinstall starts at mode Off, and mode On is
refused until a scan of the new install finds columns, even without `cache:clear`. Run `cache:clear`
anyway: until it runs, a node can keep a cached table policy. Once the package is gone, the admin
app's Data Masking and Compliance pages show DreamFactory's standard paywall, on Gold too.

---

## What changes for apps in mode On

These apply to callers who get masked values, on covered services, with masking On. In Preview and
Off, requests and response bodies are unchanged.

- **Values** come back in the column's mask format (see [Classes and formats](#classes-and-formats)).
- **Filters on masked columns match no rows.** A comparison the caller may not make on a masked
  column is unknown, like a comparison with SQL `NULL`, and a row is returned only when the whole
  filter is true. These comparisons are unknown:
  - on restricted and free-text columns: every operator except `IS NULL` and `IS NOT NULL`;
  - on identity and quasi-identifier columns: `LIKE`, `CONTAINS`, `STARTS WITH`, `ENDS WITH`, ranges
    (`<`, `>`, `<=`, `>=`), and `IN` / `NOT IN` lists of more than 25 values;
  - any function or expression over a masked column (`substr(ssn,1,3) = '123'`);
  - a filter that mentions a masked column and that Data Masking cannot parse with certainty.

  | Filter | Rows returned |
  |---|---|
  | `ssn = '123-45-6789'` | none |
  | `(state = 'IL') AND (ssn = '123-45-6789')` | none |
  | `(state = 'IL') OR (ssn = '123-45-6789')` | the IL rows |
  | `NOT (ssn = '123-45-6789')`, `ssn != '123-45-6789'` | none |
  | `email = 'jane@example.com'`, `email IN (...)` (up to 25 values) | the exact matches, as without masking |
  | `ssn IS NOT NULL` | as without masking |

  The answer never depends on the masked value, so a filter cannot be used to guess it, and an app
  that looks a record up by a masked value gets no record rather than someone else's. The response
  is still 200 and keeps DreamFactory's own shape (`count_only`, `include_count`, related records,
  JSON, XML and CSV): when nothing can match, DreamFactory receives an always-false filter such as
  `(id IS NULL) AND (id IS NOT NULL)`. This covers every spelling of the column (`customers.ssn`,
  `` `ssn` ``, `[ssn]`, `SSN`), `having`, and the filters DreamFactory uses to read related records.
  Look records up by id or by a column that is not masked.
- **Sorting, grouping and functions in `fields`** on masked columns are left out of the request, and
  the response is 200. This covers `MAX(DISTINCT ssn)`, `MAX(ssn) AS m` and the other spellings above.
  DreamFactory used to answer 400 to some of these.
- **Lookups by id** on a masked id field (`id_field=ssn`, or the primary key when it is masked)
  follow the filter rule: they are unknown for restricted and free-text id fields, and for identity
  and quasi-identifier id fields with more than 25 ids. A read is answered the way DreamFactory
  answers ids that do not exist, without running the lookup: 404 `Record with identifier '•••' not
  found.` for `_table/{table}/{id}`, and 400 `Batch Error: Not all requested records could be
  retrieved.` for `ids=` and for records sent in the body. The batch holds a 404 for the first id,
  or one per id with `continue=true`. A write by such ids gets 400 `Writes may filter masked columns (ssn) only
  by exact match (=, IN), and never restricted or free-text columns.` Identity id fields such as
  `email` with up to 25 ids work as before.
- **Writes with a filter** (PUT, PATCH, DELETE) that compares a masked column in a way the caller may
  not get the same 400. Data Masking never rewrites a write's filter, because that could change
  other rows.
- **Updates** (PUT, PATCH, MERGE) treat masked values sent back as unchanged.
- **Inserts** (POST) that contain masked values (bullets, or tokens of the column's class) get 400
  `Masked values can't be inserted. Send real values or leave the field out.` A null is a real null and
  is inserted.
- **Database errors** that can carry row data become
  `Database error during insert (SQLSTATE 23000). Data Masking removed the details.` (the operation is
  insert, update, delete, read, call or request). This applies to SQLSTATE classes 22, 23, 27, 38, 39,
  44 and P0, and to any message with DETAIL or CONTEXT lines or `key (...)=(...)`, in any server
  language. Other database errors keep their text with values removed. DreamFactory's own validation
  messages stay readable and keep the field names the caller sent, for example
  `Invalid field '1' in order by clause.`, `Invalid or unparsable field in filter request: 'nosuchcol'`
  and `Required field 'created_at' can not be NULL.`
- **Package export** (`POST system/package`) that includes covered `_table` data gets 403
  `Exporting table data needs real-value access. Ask the super admin for a grant, or export without
  table data.` Importing a package that contains masked values refuses those records (400 each).
- **Callers without a session** get masked values: scheduler tasks without a run-as app, queue, MQTT
  and AMQP workers, and `php artisan` commands that call the API. Give a scheduler task that needs
  real values a run-as app, and give that app's role real-value access (**Data Masking > Access >
  Roles**).
- **Event scripts and `platform.api` calls** are masked like the caller they run for.

Two DreamFactory behaviors to know when you write filters. DreamFactory reads `NOT` only at the
very start of a filter, so Data Masking writes the negations it produces as inverted comparisons
(`state != 'IL'`, `age <= 3`, `NOT IN`, `NOT LIKE`, `IS NOT NULL`). Parts of a filter with no unknown
comparison keep your text exactly, including `NOT`, `XOR` and `NOR`, and DreamFactory treats them as
it would without masking. DreamFactory also ignores filters sent as an array (`filter[]=...`),
so Data Masking leaves array forms (`filter[]`, `having[]`) as sent and reports nothing for them.
DreamFactory reads no `having` parameter at all; the string form is still checked in case a
connector reads it.

### Headers

Data Masking decides on the server what each caller gets, from the mode and from who is calling. It
reads no request header of its own, and nothing a client sends can turn masking off. In mode On it
adds up to two response headers that say what it changed in that response. It never reads them from
requests: sending them changes nothing.

| Response header | Example | Means |
|---|---|---|
| `X-DreamFactory-Masked-Fields` | `email, ssn, orders_by_customer_id.card_number` | These fields are masked in this response. Fields of related records appear as `relation.field`. `*` is used for `_proc`, `_func` and `_spec?model=true` responses (the `_spec` body lists the fields in `masked_columns`). |
| `X-DreamFactory-Masking-Rewrites` | `filter:ssn, order:email` | Data Masking changed these parts of the request because they use a masked field. Sent even when the response contains no masked field. |

| Rewrites item | What happened |
|---|---|
| `filter:<field>`, `having:<field>` | Conditions on the field matched no rows (see **Filters on masked columns match no rows** above). A lookup by a masked id field found no record. |
| `filter:*` | A filter Data Masking could not check matched no rows. |
| `order:<field>`, `group:<field>` | The sort or grouping was left out. |
| `fields:<field>` | A function on the field, such as `MAX(ssn)`, was left out of `fields`. |

A rewritten filter never matches a row the original filter would not. Exact matches that still work
(`email = 'jane@example.com'`, `IN` with up to 25 values, `IS NULL`) are not reported. Items from the
requests DreamFactory makes internally while serving the request are included, for example
`filter:tax_ssn` when related records joined on a masked key were withheld.

```http
GET /api/v2/crm/_table/customers/1?fields=id,email,ssn

HTTP/1.1 200 OK
X-DreamFactory-Masked-Fields: email, ssn

{"id": 1, "email": "EMAIL_7f3a9c21", "ssn": "••••••••"}

GET /api/v2/crm/_table/customers?fields=id&filter=ssn like '123%'&order=email

HTTP/1.1 200 OK
X-DreamFactory-Masking-Rewrites: filter:ssn, order:email

{"resource": []}
```

**No header** means Data Masking changed nothing in that response: the mode is Off or Preview, the
caller sees real values for every field returned, no masked field was returned, or the service is
not covered. Don't rely on it to tell whether data is protected: services Data Masking cannot cover are never masked,
and scrubbed database error text is not reported. To see what an app gets, call the API with that
app's API key (Data Explorer, **Roles with read access**, **Copy curl**).

Values are comma-separated, capped at 1024 bytes, and end with `, +N more` when cut. Names are
percent-encoded (RFC 3986, UTF-8) outside visible ASCII, and so are `%` and `,`: split on `,`, trim,
and decode each item with `decodeURIComponent` or `rawurldecode`. A browser app on another origin can
read these headers only if the instance's CORS entry lists both under exposed headers. The admin
app's Data Explorer reads them: masked columns get an icon in their header, the toolbar shows a
**Masked** chip, and a line such as `Conditions on masked columns match no rows: ssn · Sort ignored
on masked columns: email` appears under the toolbar.

**One DreamFactory request header adds masking.** A request that carries `X-DreamFactory-Trace-Id`
counts as an AI session: masked unless **Access > AI and MCP sessions** is **Same as admins**, and in
mode On refused (403) by database services Data Masking cannot cover. The MCP daemons and AI Chat
send it on every call. DreamFactory also returns it on every response for log correlation. A gateway
or SDK that copies it into later requests turns them into AI sessions: more masking, never less. The
Activity tab labels these calls `(AI session)`.

---

## How it works

### Classification

The classifier is deterministic and uses no machine learning. Each column gets a score from column
name tokens (`ssn`, `email_addr`, `dob`), sampled values checked by validators (Luhn, SSN area rules,
IBAN mod-97, email syntax, phone shapes, identifiers inside short or long free text) and table context.

| Score | Verdict | Counted as | Effect |
|---|---|---|---|
| 70 or more | `masked` | masked | masked |
| 40 to 69 | `review` | to review | masked until an admin decides (fails closed) |
| below 40 | `clear` | not sensitive | not masked |

These bands apply when values were sampled. A column classified from its name alone (warehouses
scanned without `--sample`, and new columns before their first scan) is masked at 70 or more and to
review at 15 or more.

The three counts are disjoint and add up to the total, in the admin app, the API, the CLI and the
evidence export. Admin decisions are sticky: rescans, rules and baselines only add masking and never
clear it silently.

Sampled values only live in memory. The system database stores verdicts, evidence text and
examples that are already masked, never raw values.

A column with an IP name (`x_forwarded_for`) in which free-text detection finds only IP addresses
(`unknown, 203.0.113.7`) is classed as IP address, not Free text, and masked with the IP address
format; by default the token hides the whole value. Lists made only of addresses
(`203.0.113.7, 198.51.100.4`) are detected the same way in such columns; under other names they stay
not sensitive (see [Limits](#limits-v1)).

**Computed fields.** Virtual fields, and fields with a SELECT `db_function`, inherit the strictest
masking of the masked or to-review columns their expression reads (evidence: `Built from: first_name,
email`). A partial format (last 4, initial, year, span) is kept only when the expression reads exactly
one masked column; otherwise the field is redacted. An expression that Data Masking cannot check
(a subquery, or names that are not columns of the table) is to review, redacted; the admin app shows
it as **Redact** with **Choose a class**. `COUNT(...)` alone is not masked. An admin decision on the
field itself wins. Filters on a field whose FILTER `db_function` reads masked columns are unknown,
like filters on those columns.

When the expression is later removed or changed, the field stays masked, because automatic rescans
never remove masking. Its evidence then reads `Was built from: ssn` above `An earlier scan classified
this as National ID (masked); automatic rescans never remove masking (mark it not sensitive to clear
it)`. Mark it **Not sensitive** to clear it.

### Classes and formats

There are 23 classes in 4 tiers:

- **Restricted:** national ID, tax ID, passport number, driver's license, card number, card
  security code, bank account, credential, health and special category.
- **Identity:** email, phone, person name, street address, date of birth, IP address, username,
  precise location.
- **Quasi-identifiers:** postal code, gender, age, card expiry, personal financial.
- **Free text:** free text containing personal data.

Each class has a default format and a set of allowed formats:

| Format | What it returns |
|---|---|
| `redact` | `••••••••` |
| `last4` | `•••• •••• •••• 1234` |
| `initial` | `J••• D••` |
| `year` | `1984-••-••` |
| `token` | `EMAIL_7f3a9c21`: an HMAC that is stable per instance, so you can join on it |
| `null` | `null` |
| `span` | free text only: replaces the emails, phone numbers, card numbers and IDs it detects |

Numbers and booleans come back as `null` under every format except `token`. Restricted classes never use
`token`, because hashing a list of likely values could reverse it. The token key is generated on first use and
stored encrypted with your `APP_KEY`. You can also set `DF_MASKING_TOKEN_KEY` (base64 of 32 bytes).

### Custom rules

A custom rule masks columns the classifier misses. It has a target (`name` matches column names, not
table names; `value` matches sampled values), a pattern and a class. Patterns are PCRE, written
without delimiters, case-insensitive, up to 500 characters. A pattern matches anywhere in the text
unless it is anchored with `^` and `$`.

The admin app reads each rule as a sentence and writes the pattern for you:

| Rule in the admin app | Pattern |
|---|---|
| Column name is `emp_ssn` or `social_sec` | `^(?:emp_ssn\|social_sec)$` |
| Column name contains `ssn` | `ssn` |
| Column name starts with `tax_` | `^tax_` |
| Column name ends with `_ssn` | `_ssn$` |
| Column values look like `AA######` | `^\p{L}{2}\d{6}$` |
| Column values contain `@example.com` | `@example\.com` |
| Column values start with `EMP-` | `^EMP-` |
| Column name matches regex, Column values match regex | the pattern as typed |

Several terms mean any of them. Terms are matched literally (the app escapes `.`, `(`, `|` and the
other regex characters). In `look like`, `A` is any letter and `#` any digit, in any script
(`\p{L}` and `\d` under the `u` flag); every other character is itself. Typing an example such as
`AB123456`, `Müller` or `山田-٣٤` turns it into `AA######`, `AAAAAA` or `AA-##` before anything is
sent; only that shape is tested and saved, never the example. A `#` in an example is a digit slot
too, so values that really contain `#` (`INV#00012`) need match regex.

A rule a Compliance baseline added is listed with its `title` ("Medical record, patient and chart
numbers"), which the admin app shows instead of the regex.

- **Value rules** mask a column when at least half of its sampled non-null values match, and at least
  3 do. Values are trimmed first, so space-padded `CHAR(n)` values match anchored patterns.
- **Adding a value rule** scans every active covered database again, so the rule applies without
  pressing Scan (`scan_started` in the answer). When a scan is running, the next one starts as it
  ends. An instance that was never scanned and whose mode is Off waits for its first scan, which
  applies the rule.
- **Name rules** apply to scanned columns at once, without a scan.
- **Rules only add masking.** When several rules match, the strictest class wins. A rule never
  clears or weakens a column, never changes a column an admin decided, and deleting it leaves the
  columns it masked masked.

### Modes

| Mode | Behavior |
|---|---|
| Off | No enforcement, no headers, no request activity rows. Setting changes are still logged, and AI sessions are still refused writes to the masking and baseline settings. |
| Preview | Responses unchanged, no headers. At most one "would mask" activity row per caller and table per hour, naming the columns (none when the response has no masked column). |
| On | Masks covered responses, including related records, before event scripts, caching, logging and response formatting (JSON, XML, CSV). See [What changes for apps in mode On](#what-changes-for-apps-in-mode-on). Responses report what changed in two headers (see [Headers](#headers)). |

- **Turning On** needs a completed scan that found at least one column. Before that, the API answers
  409 `Scan your databases before turning masking on.` and the CLI exits 1 with the same message. A
  scan of empty databases (a default install's built-in `db`) does not count, and only scans in this
  install's scan history count, so a reinstall starts over. `setup --mode=on` scans first.
- **Lowering from On** (to Preview or Off) needs the super admin; other admins get 403 `Only the super
  admin can lower the masking mode.` Raising the mode, and switching between Preview and Off, are
  always allowed. `php artisan df:masking mode ...` always works.
- **The first scan** that finds columns switches the mode to Preview only when nobody has chosen a
  mode yet. An Off chosen before the first scan (CLI or API) stays Off.
- **If the settings table cannot be read**, Data Masking keeps the last mode it read, or On when it
  knows none. An instance without the `dm_*` tables keeps the defaults (Off).
- **A request Data Masking cannot check** (for example because a `dm_*` table cannot be read) is
  passed through unchanged in Preview, and the error is logged (at most once a minute per PHP
  process). In mode On it is withheld: 500 `Data Masking could not check this request.` A response Data
  Masking cannot mask in mode On is withheld too: 500 `Data Masking could not mask this response, so
  it was withheld.`

### Who sees real values

| Caller | Access |
|---|---|
| Admins | Masked by default. Real-value access is `none`, `selected` (per admin, for 1h, 8h, 24h, 7d or until turned off) or `all`. To see what an app gets, call the API with that app's API key. |
| Roles | Can be given real values for all classes, or for all classes except restricted ones. |
| AI and MCP sessions | Always masked by default. The alternative is "same as admins". When the mode is On, AI sessions are blocked from database services that masking cannot cover. They can read but never change masking or baseline settings. A request that carries `X-DreamFactory-Trace-Id` counts as an AI session (see [Headers](#headers)). |
| The super admin | The df-compliance root admin. Without df-compliance, or when no root admin is designated, every full system admin is the super admin. Only the super admin can loosen: give or extend grants, widen admin access, set AI to "same as admins", enable or widen a role, or lower the mode from On. Any admin can always tighten. Marking a column not sensitive and switching a class to a less strict allowed format need a full system admin, not the super admin. |

Only full system admins can use `system/data_masking` and `system/security_baseline`, for reads and
writes. A role or API key that was granted the system service gets 403 `Only a system administrator
can view Data Masking settings.` (or `change`); blocked writes appear in the activity log. In the
admin app, a change the server refuses with 403 shows the server's reason and changes nothing on
screen.

### Covered services and scans

Covered services are every SQL service built on `df-sqldb`: MySQL, MariaDB, PostgreSQL and AlloyDB,
SQLite, SQL Server, Oracle, Snowflake, and other df-sqldb connectors. Snowflake and other warehouses
that bill per query (Databricks, Trino, Dremio, BigQuery) are classified from column names only;
sampling them is opt-in (`--sample`, or `"sample": true` with `POST /scan`).

Scans keep themselves current once any scan has run (even one of empty databases) or the mode is
Preview or On:

- Creating or changing a covered service scans it right away. Only one scan runs at a time; a scan
  requested while another runs starts when that one ends.
- A table or column that appears between scans is classified from its name on its first request and
  enforced at once. In mode On, a text column whose name says nothing is span-masked until it is
  scanned: emails, phone numbers, card numbers and national IDs in it are hidden, while UUIDs, codes,
  numbers and prose pass unchanged, so keys and joins keep working. Until then it counts as to review
  (Free text, evidence `Not scanned yet: personal data in its values is masked until a scan reads
  them`). Numbers, dates, booleans, UUID-typed and JSON columns keep their name-only verdict. In
  Preview such columns are only reported.
- Seeing such a column starts a scan of its service right away, at most once per service per minute.
  A request inside that minute is run when the minute ends (by the first request after it), never
  dropped. The scan usually replaces the name-only verdict within seconds.

When a scan cannot read a database, the scan still finishes for the others:

- The overview's `scan` has `last_status` (`done`, `partial` or `failed`) and `failed`
  (`[{service_id, service, label, reason}]`); `/table` services have `scan_error`.
- A database the last scan could not read does not count as scanned, and the Compliance check "All
  databases scanned" fails for it. Reasons carry no data, for example `Could not connect (SQLSTATE
  HY000)`.
- Once every database a scan failed on is deleted, `last_status` falls back to the previous scan that
  still concerns an existing database (or `null`), and Data Masking and Compliance stop reporting the
  failure. Deleting the database a scan was started for does not hide the failures of databases that
  still exist.
- A database that another database's scan read (a scan also reads the databases that became due
  while it ran) counts as scanned, even when it has no tables.
- Activity texts name databases by label (the name when there is none), for example `Scan failed:
  could not read Warehouse`. `df:masking scan` output and `dm_scan.error` use service names.
- When the scan history itself cannot be read, the overview's `scan.unknown` is `true` and every
  `/table` service has `scan_unknown: true`, rather than looking never scanned. The admin app then
  shows `Couldn't read the scan history. Check the DreamFactory log.` and offers no first scan.
- `df:masking scan` and `status` name each database they could not read, with the reason.
- Columns whose values cannot be read (for example a SQL Server type the driver cannot render) are
  retried one by one. Those that still fail are set to review with the evidence line `Values could not
  be read (SQLSTATE ...)` until a scan reads them. SQL Server `rowversion` columns are never sampled.

Scans only read. Every table and column name is quoted with the database's quote character doubled,
never parsed as SQL, so any column name DreamFactory can describe can be sampled, quotes, brackets and
dots included. A table DreamFactory itself cannot describe (on MySQL, for example, a table name with a
backtick) is reported as `1 table could not be read` and keeps its earlier classification. Each sample
read runs in a transaction that is always rolled back: PostgreSQL `READ ONLY` with a statement
timeout; MySQL and MariaDB `READ ONLY` with `MAX_EXECUTION_TIME`; SQL Server `SNAPSHOT` isolation when
the database has `ALLOW_SNAPSHOT_ISOLATION ON` (no shared locks on your rows), otherwise the default
isolation. Other drivers read in autocommit within a per-table time budget. On Informix only plain
identifier names can be sampled.

### Performance

Measured for this release on a development stack (DreamFactory 7.7.1, MySQL 5.7 system database,
Redis cache, shared host): `GET crm_mysql/_table/customers?limit=100` as an app, with 11 of 16 columns
masked, p50 of 100 requests per mode, client wall time. Over five runs, mode On added 5.1 to 10.8 ms
(median 8.7 ms) and Preview 0.8 to 5.0 ms; runs on the same host vary by several milliseconds. Part of
the On cost is the larger body: tokens are longer than most values (59.6 KB instead of 41.5 KB here).
Development installs (`bin/dev-install.sh`) keep the package out of Composer's optimized classmap, so
production installs cost slightly less. Requests to non-database services, and every request while
the mode is Off, make no df-masking database queries. Scanning a 50-column MySQL database takes about
a second.

---

## Compliance baselines

| Baseline | Maps to |
|---|---|
| HIPAA | HIPAA Security Rule and Privacy Rule (45 CFR 164) |
| PCI DSS | PCI DSS v4.0.1 |
| GLBA | FTC Safeguards Rule (16 CFR 314, non-bank financial institutions) and the Interagency Guidelines (banks: 12 CFR 30 App. B, 208 App. D-2, 364 App. B; credit unions: 12 CFR 748 App. A) |
| CJIS | FBI CJIS Security Policy v6.1 (control IDs such as AC-6, AU-11 and SC-28, which v5.9.5 uses too) |
| GDPR | EU GDPR (Regulation (EU) 2016/679) |
| SOC 2 | AICPA 2017 Trust Services Criteria (With Revised Points of Focus, 2022) |
| ISO 27001 | ISO/IEC 27001:2022 |

References were re-checked on 2026-10-29 against CJISSECPOL v6.1 and v5.9.5, eCFR, PCI SSC SAQ D
v4.0.1, Cornell LII and gdpr-info.eu. They are not legal advice.

**Apply** only tightens. It never loosens a setting, clears masking or removes an admin decision, and
rules it adds stay after you stop tracking. Apply with masking On is refused (409) until a scan has
found columns. Apply on an instance where no scan has found columns yet starts a scan
(`scan_started: true`).

Checks worth knowing:

- Masking checks never pass before the first scan, and a database the last scan could not read counts
  as not scanned. "All databases scanned in the last 30 days" becomes a manual check when there are
  database services Data Masking cannot scan (MongoDB, DynamoDB, Cassandra...).
- Check details name databases by their label (the service name when there is no label), as Data
  Masking does: `The last scan couldn't read Warehouse.`
- If the scan history cannot be read (a system database error), the masking checks say `Could not be
  checked: see the DreamFactory log.` with a link to Data Masking, never "never scanned". The review
  and "marked not sensitive" checks keep their counts when the column table shows a problem. The JSON
  report then has `masking.inventory.scan_history_error`.
- "No ... marked not sensitive" counts only columns detected with a score of 70 or more: rejecting a
  to-review suggestion does not fail it. HIPAA also protects age, tax IDs, free text and usernames;
  GDPR also protects direct identifiers (email, phone, name, address, date of birth, IP, username).
- "Roles never see restricted real values" (PCI DSS: "Roles never see full card data") fails when a
  role has real-value access that includes restricted classes.
- "A super admin approves real-value access" passes when a df-compliance root admin is designated
  (`A super admin is designated: only they can give access to real values or lower the masking mode.`).
  It fails when none is designated (fix: `php artisan df:root_admin --admin_id=<id>`) and without
  df-compliance.
- "Reads from every SQL database are logged" passes when the MongoDB request log is on, or when an
  active Logstash service gets `<svc>._table.{table_name}.get` and `<svc>._table.{table_name}.{id}.get`
  (or `<svc>.*`) for every covered SQL service.
- "Idle sessions require signing in again after N minutes" also needs `DF_JWT_REFRESH_TTL` at or below
  N (15 for PCI DSS, 30 for CJIS, 60 for HIPAA, GLBA and ISO 27001), because DreamFactory renews an
  expired token without credentials until `refresh_ttl` after sign-in (default 14 days). The
  trade-off: users sign in again at least every N minutes, even while active.
- Other automatic checks: admins unused for 90 days, open user registration, masking activity kept for
  a year (`DF_MASKING_ACTIVITY_RETENTION_DAYS` of 365 or more, or 0), debug mode, HTTPS, CORS and rate
  limits.
- Infrastructure controls (encryption at rest, backups, agreements...) are manual items.

**Evidence exports** (`/report?format=json|csv`) contain no data values. `format=csv` always returns
`text/csv; charset=utf-8` as an attachment named `dreamfactory-<id>-baseline-YYYY-MM-DD.csv`, whatever
the `Accept` header or DreamFactory's `accept=` parameter says. `format=json` is a normal DreamFactory
response (`download=true` adds an attachment header). Every CSV row carries `frameworks` and
`disclaimer` columns, and the JSON report carries both fields.

---

## Console

```bash
php artisan df:masking status [--json]
php artisan df:masking scan [--service=NAME] [--sample]
php artisan df:masking mode off|preview|on
php artisan df:masking grant ADMIN_EMAIL [--for=1h|8h|24h|7d|forever]
php artisan df:masking revoke ADMIN_EMAIL | --all
php artisan df:masking baseline list | apply ID [--mode=on]
php artisan df:masking setup [--baseline=ID] [--mode=preview|on]
```

The console is the recovery path when nobody can reach the admin UI. Shell access means you are the
operator, so every subcommand can tighten and loosen, and changes are logged as "Command line".
Typical recovery: `revoke --all` (every admin masked again), `mode off`, or `grant you@example.com
--for=1h` when no admin can see real values and the super admin is away. `mode on` and `baseline apply
--mode=on` exit 1 until a scan has found columns. `baseline apply` on an instance where no scan has
found columns yet starts one and prints `First scan started: php artisan df:masking status`. Run
artisan as the web user (`www-data`) where you can; run as root, `df:masking` hands the files it
creates under `storage/` back to their owner. When the license level is not Gold, only `status`,
`help`, `revoke` and `mode off` run; the other subcommands exit 1 with the license message.

## API summary

Both APIs are system resources (Gold) under `/api/v2/system/`, for full system admins only, on an
instance whose license level is Gold (403 otherwise). Bodies are snake_case, and errors use
DreamFactory's standard error envelope.

### `data_masking`

| Method and path | Purpose |
|---|---|
| `GET /data_masking` | Overview: `mode`, `scan` (`status` `idle` or `running`, `progress`, `finished_at`, `columns`, `last_status`, `failed`, `unknown`: true when the scan history could not be read), `counts` (`masked`, `review`, `clear`), `you`, `coverage` |
| `PATCH /data_masking` | Set the mode: `{mode: off\|preview\|on}` (409 until a scan has found columns; lowering from On needs the super admin) |
| `GET /data_masking/table` | Classified tables per covered service, with a per-column strip, `scanned_at` (null = never scanned), `scan_error` and `scan_unknown` (true when the scan history could not be read) |
| `GET /data_masking/column?service=&table=` | Columns with verdict, class, confidence, evidence and a masked example |
| `PATCH /data_masking/column` | Decide a column: `{id: "service.table.column", class: <id>\|null}` (null = not sensitive). Works for any column name. The path form `PATCH /data_masking/column/{id}` still works. |
| `POST /data_masking/scan` | Start a background scan: `{service?, sample?}`. Idempotent while a scan runs. |
| `GET` and `PATCH /data_masking/access` | Admins (mode, grants), AI, roles, and `version`. Send `version` back with PATCH: if access changed since, the answer is 409 `Access settings changed since you loaded them. Reload and try again.` (the admin app shows `Access settings changed elsewhere. Showing the latest.` and re-reads). New grants need a duration; a grant sent without one must still be live (409 otherwise). `roles` may list only the roles you change. |
| `GET` and `PATCH /data_masking/mask` | Format per class: `{resource:[{class, format}]}` |
| `GET` and `POST /data_masking/rule` | Custom rules: `{match: name\|value, pattern, class}`. PCRE, case-insensitive, up to 500 characters (see [Custom rules](#custom-rules)). Each rule has `matches`: how many scanned columns it matched. Rules a baseline added also have `title`. POST also answers `scan_started`: true when adding a value rule started a scan, or one starts when the running scan ends. |
| `DELETE /data_masking/rule/{id}` | Delete a rule. Columns it masked stay masked. |
| `POST /data_masking/rule/test` | Preview a rule's matches: `{match, pattern}` returns `{matches:[{id}], partial}` |
| `GET /data_masking/rule/builtin` | The built-in detectors per class |
| `GET /data_masking/activity?kind=&limit=&before=` | Activity, newest first. `kind` is one kind or a comma list (`mode`, `decision`, `access`, `scan`, `blocked`, `rule`, `baseline`, `preview`); `limit` defaults to 200 (max 1000); `before=<activity id>` pages back. Returns `has_more`. Rule rows also carry `match` (`name` or `value`), so their `target`, the pattern, reads back as the rule. Filters on masked columns appear under `blocked` as `Conditions on a masked column matched no rows` (or `A filter Data Masking could not check matched no rows`). |

### `security_baseline`

| Method and path | Purpose |
|---|---|
| `GET /security_baseline` | All baselines, with live scores |
| `GET /security_baseline/{id}[?mode=on]` | Controls with pass, fail, manual or n/a status, framework references, and the exact `changes` Apply would make (with `mode=on`: Apply with masking On) |
| `POST /security_baseline/{id}/apply` | Adopt the baseline: `{mode?: 'on'}`. Returns `scan_started`. 409 for `mode: 'on'` until a scan has found columns. |
| `DELETE /security_baseline/{id}` | Stop tracking. Settings stay. |
| `GET /security_baseline/{id}/report?format=json\|csv[&download=true]` | Evidence export. CSV (always `text/csv`, as an attachment) columns: `baseline_id, baseline, control_id, title, status, detail, references, generated_at, frameworks, disclaimer`. |

AI and MCP sessions get a 403 on every write. Every write is recorded in the activity log.

## Configuration

`config/df-masking.php` reads every value from the environment:

| Variable | Default | Meaning |
|---|---|---|
| `DF_MASKING_TOKEN_KEY` | (generated) | Token HMAC key, base64 of 32 bytes |
| `DF_MASKING_ACTIVITY_RETENTION_DAYS` | 400 | Activity rows older than this are pruned. 0 keeps them forever. |
| `DF_MASKING_RULE_TEST_BUDGET_MS` | 3000 | Time budget for value-rule tests |
| `DF_MASKING_RULE_BACKTRACK_LIMIT` | 100000 | PCRE backtrack limit while admin patterns run |
| `DF_MASKING_SCAN_STALE_MINUTES` | 5 | A scan with no heartbeat for this long is reported as failed |
| `DF_MASKING_ACCESS_CACHE_SECONDS` | 30 | Longest time a grant or role decision is cached. Writes apply immediately. |
| `DF_MASKING_PHP_BINARY` | (found) | PHP CLI binary for the detached scan process. Without it: `PHP_BINARY` when running from the CLI, then the PHP executable on the path, `/usr/bin/php`, `/usr/local/bin/php`. When none is found or `proc_open` is disabled, the scan runs inside the request. |
| `DF_MASKING_SCAN_TABLE_BUDGET_MS` | 20000 | Sampling time budget per table |
| `DF_MASKING_SCAN_STATEMENT_TIMEOUT_MS` | 10000 | Per-statement timeout while sampling (PostgreSQL and MySQL; elsewhere the table budget is checked between statements) |

New columns start a scan of their service at once, at most once per service per minute.

Masking policy (mode, column decisions, access, formats, rules) lives in the system database, not in
this file, and the cache must be shared between nodes (see [Several DreamFactory nodes](#several-dreamfactory-nodes)).

## Limits (v1)

- **Event scripts that set or change filters are not checked.** A `pre_process` script runs after the
  request guard, so a filter, order or group it adds on a masked column runs on real values, and its
  results can reveal those values. Event scripts are admin-authored code with full trust; changing
  their filters would silently change results (for example tenant scoping). Mitigation: limit who can
  edit event scripts (give non-admin roles no access to `system/event_script`) and review scripts that
  build filters from request parameters.
- **SQL services only.** MongoDB, Cassandra, CouchDB, DynamoDB, Salesforce and other database services
  are not masked. Humans and apps keep normal access to them; AI sessions are blocked from them while
  the mode is On.
- **Scripts that open their own database connections** do not go through the API, so they are not masked.
- **Names inside free text** are not detected. Span masking covers emails, phone numbers, cards,
  national IDs, IBANs, IP addresses and credentials.
- **Lists of IP addresses** (`203.0.113.7, 198.51.100.4`, typical of `x_forwarded_for`) are detected
  as IP address only in columns whose name suggests IP addresses (`x_forwarded_for`, `client_ip`, ...).
  The same lists under other names (`hops`) stay not sensitive, to keep false positives down: add a
  name rule (for example `{match: "name", pattern: "^hops$", class: "ip_address"}`) or decide the
  column as IP address.
- **New tables and columns** are classified from their names until their scan finishes (seconds, or
  minutes on large databases). In mode On, text columns among them are span-masked meanwhile. They use
  the Free text format: if you changed it from `span` to `redact` or `null`, those columns, keys
  included, are fully hidden until their scan finishes. A database the scanner cannot read keeps its
  new text columns masked and to review until a scan succeeds.
- **Tables keyed on a restricted or free-text masked column** cannot be read or edited by id by masked
  callers: reads answer 404 and writes 400 (see [lookups by id](#what-changes-for-apps-in-mode-on)).
  Data Explorer edits of such rows show the write message.
- **Relationships keyed on a masked column** (for example on email) can return empty related records
  for masked callers. Fails closed.
- **Computed fields stay masked** after their expression is removed or changed, until an admin marks
  them not sensitive (evidence `Was built from: ...`).
- **Upserts.** On services with `allow_upsert`, a PUT or PATCH that ends up inserting a row stores
  NULL for masked fields that were stripped as unchanged.
- **Stored procedures and functions** (`_proc`, `_func`) are masked on a best-effort basis: result
  cells by column name, and spans in every other string.
- **Internal `_spec` calls** from server-side scripts are not intercepted. HTTP `_spec` model requests
  are (sample data and enum values masked), in every URL form.
- **Masking configuration is not part of package export.** `system/package` does not offer Data
  Masking or Compliance settings. Re-apply them, or apply the same baseline, on the target instance.
- **Per-node caches** are not supported: every node must use the same cache store (see
  [Several DreamFactory nodes](#several-dreamfactory-nodes)).
- **AI detection** covers the MCP daemons (they send `X-DreamFactory-Trace-Id` on every call), df-agents
  agent keys and df-ai-chat. A non-AI client or gateway that forwards `X-DreamFactory-Trace-Id`
  (DreamFactory returns one on every response) is treated as an AI session: masked values even when
  its role has real-value access, and in mode On 403 from services masking cannot cover. Don't
  forward it from non-AI clients. Not detected as AI: admin-defined MCP custom tools that call the data API, script callbacks
  made over HTTP, and an LLM driving a human's credentials directly.
- **GraphQL type nullability** is not adjusted for masked columns.
- **PostgreSQL partitioned tables without a primary key** may be under-sampled.
- **Statement timeouts** while sampling are enforced on PostgreSQL and MySQL only.
- DreamFactory itself may write database error text, which can include submitted values, to its own
  log. df-masking never logs values.

## System databases

The `dm_*` tables hold no raw values. Install, scans, column decisions, access and mode changes, and
enforcement were verified for this release on these DreamFactory system databases: MySQL 5.7,
PostgreSQL 16, SQL Server 2022 and SQLite (the trial default); the `dm_scan.scope` migration was run
up, back down and up again on MySQL 5.7, PostgreSQL 16 and SQL Server 2022, and the
`dm_scan.read_services` migration on MySQL 5.7. MariaDB takes the MySQL
code path but was not tested separately.

## Development

```bash
# Offline install into a running DreamFactory container. Mount the package at /src/df-masking.
# Idempotent: symlinks the package into vendor/, registers it in installed.json, runs composer
# dump-autoload, package:discover and migrate, and clears caches. Stops with an error (and rolls the
# registration back) when the package does not autoload or a migration fails.
bin/dev-install.sh <container>

# Unit tests: the image's PHP and a PHPUnit 11 phar, in a throwaway container (--network none)
bin/test.sh [--testsuite Platform|Classifier|Scanner|Masking|Enforcement|Baselines|Integration]

# Live suites against a running stack (see tests/Live/README.md)
tests/Live/run.sh all
```

Opt-in tests: `tests/Unit/Scanner/SystemDbPortabilityTest.php` runs against real system databases
(`DM_SYSDB_URLS='pgsql://u:p@host:5432/db;mysql://...;sqlsrv://...'`, empty throwaway databases; run it
on a docker network that reaches them, not through `bin/test.sh`), and
`tests/Unit/Classifier/SpikeParityTest.php` compares against the reference corpus (`DM_SPIKE_DIR`).

| Path | Contents |
|---|---|
| `src/Support` | Shared building blocks: catalog, settings, policy version, activity, caller, access, coverage, formats, rule patterns, scan history, retries |
| `src/Resources` | The `data_masking` and `security_baseline` system resources (handlers in `Resources/Handlers`) |
| `src/Classifier`, `src/Scanner` | The classification engine and scans |
| `src/Masking`, `src/Enforcement` | Mask formats and request/response enforcement |
| `src/Baselines` | Compliance baselines |
| `src/Console` | `df:masking` |
| `database/migrations` | `dm_*` tables, portable across MySQL/MariaDB, PostgreSQL, SQLite and SQL Server |
| `tests/Unit/<Area>` | PHPUnit suites (`Integration` holds regression tests for the cross-area wiring) |
| `tests/TestCase.php` | An isolated Laravel harness |
| `tests/Live` | Scripts that check a running instance end to end |

## License

Commercial software, part of the DreamFactory Gold package, licensed under the DreamFactory Terms of
Use in [LICENSE](LICENSE). Copyright DreamFactory Software, Inc. Support: dspsupport@dreamfactory.com.

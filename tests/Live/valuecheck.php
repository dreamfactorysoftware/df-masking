<?php
// Live stored-value check (run inside the DreamFactory web container after a full scan):
//   docker exec -i <web container> php -d memory_limit=1G < valuecheck.php
// Re-samples every covered service exactly like the scanner (same Sampler, same windows), keeps
// the distinctive sampled strings in memory, then searches every dm_* table and every file in
// storage/logs for them (raw and JSON-escaped). Prints counts and, for hits, only a hash prefix,
// the length and the location - never a value.
chdir('/opt/dreamfactory');
require '/opt/dreamfactory/vendor/autoload.php';
$app = require '/opt/dreamfactory/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use DreamFactory\Core\Masking\Scanner\Sampler;
use DreamFactory\Core\Masking\Scanner\SchemaReader;
use DreamFactory\Core\Masking\Scanner\Services;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Support\Catalog;
use Illuminate\Support\Facades\DB;

$values = [];   // value => "service.table.column"
$schemaWords = [];
foreach (Services::covered() as $info) {
    $svc = app('df.service')->getService($info['name']);
    if (Services::isMissingSqliteFile($svc)) {
        // Like the scanner: connecting would create the empty file (the built-in `db` service).
        // A verification tool leaves the instance as it found it.
        continue;
    }
    $reader = new SchemaReader($svc);
    $driver = $reader->driver();
    if (Services::isCostBearing($driver, $info['type'])) {
        continue;
    }
    $sampler = new Sampler($svc->getConnection(), $driver);
    foreach ($svc->getTableNames() as $ts) {
        $full = $svc->getTableSchema($ts->name);
        if (!is_object($full)) {
            continue;
        }
        $d = SchemaReader::describe($full, $driver);
        $schemaWords[strtolower($d['meta']->dfName)] = true;
        $schemaWords[strtolower($d['meta']->name)] = true;
        foreach ($d['meta']->columns as $c) {
            $schemaWords[strtolower($c->name)] = true;
        }
        $s = $sampler->sample($d['meta'], $d['plan']);
        foreach ($s['rows'] as $row) {
            foreach ($row as $col => $v) {
                if ($v === null) {
                    continue;
                }
                $v = trim($v);
                // the prototype's criterion: >= 4 chars with a letter, or >= 6 digits
                if ((strlen($v) >= 4 && preg_match('/\p{L}/u', $v)) || preg_match('/^\d{6,}$/', $v)) {
                    $values[$v] ??= $info['name'] . '.' . $d['meta']->dfName . '.' . $col;
                }
            }
        }
        unset($s);
    }
}
// Words that are not data: schema names, rule-pack vocabulary, class ids, UI/engine wording.
$allowed = $schemaWords;
foreach (Ruleset::pack()->vocab() as $w => $_) {
    $allowed[(string) $w] = true;
}
foreach (Catalog::ids() as $id) {
    $allowed[$id] = true;
    $allowed[strtolower(Catalog::label($id))] = true;
}
foreach (['true', 'false', 'null', 'masked', 'review', 'clear', 'detected', 'admin', 'rule', 'baseline', 'restricted', 'identity', 'quasi', 'free_text',
    'system', 'none', 'selected', 'preview', 'off', 'token', 'redact', 'initial', 'last4', 'year', 'span', 'values', 'context', 'name', 'text', 'penalty',
    'done', 'running', 'failed', 'command line', 'kevin admin', 'priya shah', 'active', 'string', 'integer', 'date', 'email', 'phone',
    // log line boilerplate: Monolog level names and the channel (APP_ENV) prefix ("local.ERROR:")
    'debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency', 'local', 'production'] as $w) {
    $allowed[$w] = true;
}

// DreamFactory user display names (activity texts name the admins involved).
foreach (DB::table('user')->get(['name', 'first_name', 'last_name']) as $u) {
    foreach ([$u->name, $u->first_name, $u->last_name] as $n) {
        foreach (preg_split('/\s+/', strtolower(trim((string) $n))) ?: [] as $part) {
            if ($part !== '') {
                $allowed[$part] = true;
            }
        }
    }
}

// DreamFactory service names are configuration, not data: the scanner's own log lines name the
// services it could not read ("could not read service 'x'", "scan N failed: could not read x, y"),
// including services deleted since (a data value equal to such a name is a collision, not a match).
foreach (DB::table('service')->get(['name']) as $s) {
    $allowed[strtolower((string) $s->name)] = true;
}
foreach (glob('/opt/dreamfactory/storage/logs/*') ?: [] as $f) {
    foreach (is_file($f) ? (file($f) ?: []) : [] as $line) {
        if (preg_match("/df-masking: could not read service '([^']+)'/", $line, $m)) {
            $allowed[strtolower($m[1])] = true;
        }
        if (preg_match('/df-masking: scan \d+ failed: could not read (.+?)\s*$/', $line, $m)) {
            foreach (explode(', ', $m[1]) as $n) {
                $allowed[strtolower(trim($n))] = true;
            }
        }
    }
}

// Haystacks: every dm_* table, row by row; every log file.
$hay = [];
foreach (['dm_column', 'dm_activity', 'dm_scan', 'dm_setting', 'dm_rule', 'dm_mask_format', 'dm_admin_grant', 'dm_role_access', 'dm_baseline'] as $table) {
    try {
        foreach (DB::table($table)->get() as $i => $row) {
            $r = (array) $row;
            $key = $table . '#' . ($r['id'] ?? $r['name'] ?? $r['class'] ?? $r['role_id'] ?? $r['baseline_id'] ?? $i);
            foreach ($r as $field => $val) {
                // fingerprint: sha256 of schema facts; table/column names: schema identifiers;
                // actor/decided_by/created_by/...: DreamFactory user display names. None of them is data.
                if ($val === null || in_array($field, ['fingerprint', 'table_name', 'column_name', 'actor', 'decided_by', 'created_by', 'updated_by', 'triggered_by', 'adopted_by'], true)) {
                    continue;
                }
                $hay[$key . '.' . $field] = is_string($val) ? $val : json_encode($val);
            }
        }
    } catch (Throwable $e) {
        fwrite(STDERR, "skip $table: " . get_class($e) . "\n");
    }
}
$logFiles = glob('/opt/dreamfactory/storage/logs/*') ?: [];
foreach ($logFiles as $f) {
    if (!is_file($f)) {
        continue;
    }
    $mine = $other = '';
    foreach (file($f) as $line) {
        if (str_contains($line, 'df-masking')) {
            $mine .= $line;
        } else {
            $other .= $line;
        }
    }
    $hay['log:' . basename($f) . ':df-masking-lines'] = $mine;
    $hay['log:' . basename($f) . ':other-lines'] = $other;
}
$bytes = array_sum(array_map('strlen', $hay));
$found = $collisions = 0;
$report = [];
foreach ($values as $v => $src) {
    $v = (string) $v;
    $esc = substr(json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), 1, -1);
    // Whole-token match: a short value inside a longer word or hex string is not a match.
    $re = '/(?<![\\p{L}\\p{N}_])(?:' . preg_quote($v, '/') . '|' . preg_quote($esc, '/') . ')(?![\\p{L}\\p{N}_])/u';
    $distinctive = strlen($v) >= 8 || preg_match('/[\d@]/', $v);
    foreach ($hay as $where => $h) {
        if (str_ends_with($where, ':other-lines') && !$distinctive) {
            continue; // other components' log boilerplate shares common words with data
        }
        if (!str_contains($h, $v) && !str_contains($h, $esc)) {
            continue;
        }
        if (@preg_match($re, $h, $mm, PREG_OFFSET_CAPTURE) !== 1) {
            continue;
        }
        if (isset($allowed[strtolower($v)])) {
            $collisions++;
            break;
        }
        $found++;
        if (count($report) < 20) {
            $at = $mm[0][1];
            $ctx = substr($h, max(0, $at - 70), min(70, $at)) . '<VALUE ' . DreamFactory\Core\Masking\Classifier\Profiler::shape($v) . '>' . substr($h, $at + strlen($mm[0][0]), 40);
            $report[] = sprintf("  value len=%d sha256=%s sampled from %s found in %s\n      ...%s...", strlen($v), substr(hash('sha256', $v), 0, 12), $src, $where, str_replace("\n", ' ', $ctx));
        }
        break;
    }
}
printf("valuecheck: %d distinctive sampled strings from %d services checked against %d dm_* rows and %d log files (%d bytes): %d matches, %d schema/vocabulary collisions ignored\n",
    count($values), count(Services::covered()), count($hay) - count($logFiles), count($logFiles), $bytes, $found, $collisions);
echo implode("\n", $report), $report ? "\n" : '';
exit($found > 0 ? 3 : 0);

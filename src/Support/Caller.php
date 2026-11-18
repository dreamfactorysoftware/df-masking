<?php

namespace DreamFactory\Core\Masking\Support;

use DreamFactory\Core\Utility\Session;

/**
 * Who is calling: resolved once per request context and memoised.
 *
 * The memo key combines the current HTTP request object with the session's user, role and app,
 * so internal sub-requests made with the same session (event scripts' platform.api, ...) reuse
 * it, while a long-running process that switches sessions (queue worker, tests) re-resolves.
 *
 * - isSysAdmin(): DreamFactory's own rule (Session::isSysAdmin: is_sys_admin and no role, i.e.
 *   not a df-compliance restricted admin).
 * - isSuperAdmin(): may loosen access. The df-compliance root admin; when df-compliance is not
 *   installed or no root admin is designated, any full sys admin. Never an AI session.
 * - isAi(): see aiSignal().
 * - label(): what the Activity tab shows ("Alex Admin", "Alex Admin (AI session)",
 *   "API key: mobile-app", "System").
 */
final class Caller
{
    public const HEADER_TRACE_ID = 'X-DreamFactory-Trace-Id';

    private const COMPLIANCE_ADMIN = 'DreamFactory\\Core\\Compliance\\Models\\AdminUser';

    private static ?self $memo = null;
    private static ?string $memoKey = null;

    private ?bool $superAdmin = null;

    private function __construct(
        private readonly ?int $userId,
        private readonly ?int $roleId,
        private readonly ?int $appId,
        private readonly bool $sysAdmin,
        private readonly ?string $userName,
        private readonly ?string $aiSignal,
        private readonly bool $console,
        private readonly bool $aiFromTraceHeader = false,
    ) {
    }

    public static function current(): self
    {
        $context = self::context();
        $key = implode('|', [
            $context['request_id'],
            $context['user_id'] ?? '-',
            $context['role_id'] ?? '-',
            $context['app_id'] ?? '-',
            $context['sys_admin'] ? 1 : 0,
        ]);
        if (self::$memo !== null && self::$memoKey === $key) {
            return self::$memo;
        }

        $request = $context['request'];
        $fromTrace = false;
        self::$memo = new self(
            $context['user_id'],
            $context['role_id'],
            $context['app_id'],
            $context['sys_admin'],
            $context['user_name'],
            self::aiSignal($request, $context, $fromTrace),
            $context['console'],
            $fromTrace,
        );
        self::$memoKey = $key;

        return self::$memo;
    }

    /** Drops the memo (tests; long-running processes after a session switch). */
    public static function forget(): void
    {
        self::$memo = null;
        self::$memoKey = null;
    }

    public function isSysAdmin(): bool
    {
        return $this->sysAdmin;
    }

    public function userId(): ?int
    {
        return $this->userId;
    }

    public function roleId(): ?int
    {
        return $this->roleId;
    }

    public function appId(): ?int
    {
        return $this->appId;
    }

    public function isAi(): bool
    {
        return $this->aiSignal !== null;
    }

    /** True for `php artisan` with no session (scanner, df:masking): the operator. */
    public function isConsole(): bool
    {
        return $this->console && $this->userId === null;
    }

    /** The caller is an AI session because the request carries X-DreamFactory-Trace-Id. */
    public function aiFromTraceHeader(): bool
    {
        return $this->aiSignal !== null && $this->aiFromTraceHeader;
    }

    public function isSuperAdmin(): bool
    {
        if ($this->superAdmin !== null) {
            return $this->superAdmin;
        }
        if (!$this->sysAdmin || $this->isAi() || $this->userId === null) {
            return $this->superAdmin = false;
        }

        return $this->superAdmin = self::isRootAdminOrNoRootDesignated($this->userId);
    }

    public function label(): string
    {
        $base = $this->userName;
        if ($base === null && $this->appId !== null) {
            $base = 'API key: ' . (self::appName($this->appId) ?? ('app ' . $this->appId));
        }

        if ($this->aiSignal !== null) {
            $client = ($this->aiSignal !== '' && $this->aiSignal !== 'ai') ? $this->aiSignal : null;

            return ($client ?? $base ?? 'Anonymous') . ' (AI session)';
        }
        if ($base !== null) {
            return $base;
        }

        return $this->console ? Activity::SYSTEM : 'Anonymous';
    }

    /** Whether a root admin rule applies: df-compliance installed AND a root admin designated. */
    public static function rootAdminDesignated(): bool
    {
        if (!class_exists(self::COMPLIANCE_ADMIN)) {
            return false;
        }
        try {
            return (bool)call_user_func([self::COMPLIANCE_ADMIN, 'doesRootAdminExist']);
        } catch (\Throwable $e) {
            // is_root_admin column missing (df-compliance not migrated): no root admin.
            return false;
        }
    }

    /** True when $userId is the root admin, or when no root admin rule applies. */
    public static function isRootAdminOrNoRootDesignated(int $userId): bool
    {
        if (!self::rootAdminDesignated()) {
            return true;
        }
        try {
            return (bool)call_user_func([self::COMPLIANCE_ADMIN, 'isRootById'], $userId);
        } catch (\Throwable $e) {
            return false;
        }
    }

    // ------------------------------------------------------------------------------------------
    // AI session detection
    // ------------------------------------------------------------------------------------------

    /**
     * Returns null for a non-AI caller, otherwise a non-null marker: the AI client's display name
     * when known (e.g. "Claude Desktop"), or 'ai' when only the fact is known.
     *
     * The signals must be ones the LLM itself cannot remove: they are added by DreamFactory's
     * own MCP daemon / agent runtime, never taken from tool arguments.
     *
     * @param \Illuminate\Http\Request|null $request
     * @param array                         $context   see context()
     * @param bool                          $fromTrace set to true when signal 1 (the trace header) decided
     */
    private static function aiSignal($request, array $context, bool &$fromTrace = false): ?string
    {
        $fromTrace = false;
        // 1. The df-mcp-server daemon sets X-DreamFactory-Trace-Id on every DreamFactory call it
        //    makes (daemon/src/services/dreamfactory.service.ts); df-ai-chat's tool clients send
        //    it too. Residual risk: it is DreamFactory's generic trace header (df-core TraceId,
        //    echoed on every response), so a non-AI client that propagates trace ids is treated
        //    as AI. That errs on the masked side (more masking; when mode is On, a 403 from
        //    database services masking cannot cover) and never reveals data.
        if (self::header($request, self::HEADER_TRACE_ID) !== null) {
            $fromTrace = true;

            return 'ai';
        }

        // 2. HOOK (enforcement owner): session token minted by df-mcp-server's MCP OAuth flow.
        if (($signal = self::aiSignalFromMcpOAuth($request, $context)) !== null) {
            return $signal;
        }

        // 3. HOOK (enforcement owner): calls made by df-ai-chat / df-agents.
        if (($signal = self::aiSignalFromAgents($request, $context)) !== null) {
            return $signal;
        }

        return null;
    }

    /**
     * MCP OAuth sessions (enforcement research, df-mcp-server 7.7.1). Deliberately returns null.
     *
     * The MCP OAuth flow stores the DreamFactory JWT its MCP access token stands for in
     * mcp_oauth_access_token.df_session_token, but that JWT is not exclusive to the AI: on the
     * SSO path (McpOAuthController::authorize -> getExistingDfSession) it is the admin's own
     * browser session token, read from the admin UI's session_token cookie. Treating such a
     * token as an AI session would mask the admin's own console and lock them out of masking
     * settings until the MCP token expires. And it is not needed for the daemon: every call the
     * MCP daemons make carry X-DreamFactory-Trace-Id (signal 1), because the PHP proxy
     * (McpDaemonClient::proxyRequest) always sends one and both daemons re-attach it.
     * Residual risk, documented in the README: admin-defined MCP "custom tools" that call
     * DreamFactory's own data API do not add the trace header; they run as the OAuth user (or
     * API key app) and get that identity's access.
     *
     * @param \Illuminate\Http\Request|null $request
     */
    private static function aiSignalFromMcpOAuth($request, array $context): ?string
    {
        return null;
    }

    /**
     * df-agents and df-ai-chat (enforcement research, 7.7.1), identified by markers their own
     * runtimes create and an LLM cannot remove:
     *  - df-agents: AgentKeyTtl (df.api middleware, before any API event) binds the agent that
     *    owns the request's API key as 'df.agent'; agent keys also belong to a backing app
     *    named "agent:<id>" (Agent::backingAppName), which covers internal sub-requests.
     *  - df-ai-chat: tool calls run under an auto-provisioned app "ai-agent-app-role-<id>" and
     *    user "ai-agent-role-<id>@dreamfactory.local" (AiAgentCredentials); they also send the
     *    trace header (DataToolClient), so this is a second line.
     * Lookups are DreamFactory's own cached app info and the session: no query on a warm cache.
     *
     * @param \Illuminate\Http\Request|null $request
     */
    private static function aiSignalFromAgents($request, array $context): ?string
    {
        try {
            if (function_exists('app') && app()->bound('df.agent')) {
                $agent = app('df.agent');
                $name = is_object($agent) && isset($agent->name) && is_string($agent->name) ? trim($agent->name) : '';

                return $name !== '' ? 'Agent ' . $name : 'ai';
            }
        } catch (\Throwable $e) {
            // container without the binding: fall through to the app/user markers
        }

        $appId = $context['app_id'] ?? null;
        if (is_int($appId) && ($appName = self::appName($appId)) !== null) {
            if (preg_match('/^agent:\d+$/', $appName) === 1) {
                return 'ai';
            }
            if (preg_match('/^ai-agent-app-role-\d+$/', $appName) === 1) {
                return 'AI Chat';
            }
        }

        if (($context['user_id'] ?? null) !== null) {
            try {
                $email = Session::get('user.email');
            } catch (\Throwable $e) {
                $email = null;
            }
            if (is_string($email) && preg_match('/^ai-agent-role-\d+@dreamfactory\.local$/i', $email) === 1) {
                return 'AI Chat';
            }
        }

        return null;
    }

    // ------------------------------------------------------------------------------------------
    // Context
    // ------------------------------------------------------------------------------------------

    /**
     * @return array{request:\Illuminate\Http\Request|null,request_id:string,user_id:?int,role_id:?int,app_id:?int,sys_admin:bool,user_name:?string,console:bool,session_token:?string}
     */
    private static function context(): array
    {
        $request = null;
        try {
            if (function_exists('app') && app()->bound('request')) {
                $request = app('request');
            }
        } catch (\Throwable $e) {
            $request = null;
        }

        $console = false;
        try {
            $console = app()->runningInConsole();
        } catch (\Throwable $e) {
        }

        $userId = $roleId = $appId = null;
        $sysAdmin = false;
        $userName = null;
        $token = null;
        try {
            $userId = self::intOrNull(Session::getCurrentUserId());
            $roleId = self::intOrNull(Session::getRoleId());
            $appId = self::intOrNull(Session::get('app.id'));
            $sysAdmin = $userId !== null && Session::isSysAdmin();
            if ($userId !== null) {
                $userName = self::displayName();
            }
            $token = Session::getSessionToken();
            $token = is_string($token) && $token !== '' ? $token : null;
        } catch (\Throwable $e) {
            // No session store (bare console): System.
        }

        return [
            'request' => $request,
            'request_id' => $request ? (string)spl_object_id($request) : 'none',
            'user_id' => $userId,
            'role_id' => $roleId,
            'app_id' => $appId,
            'sys_admin' => $sysAdmin,
            'user_name' => $userName,
            'console' => $console,
            'session_token' => $token,
        ];
    }

    private static function displayName(): ?string
    {
        foreach (['user.display_name', 'user.name'] as $key) {
            $value = Session::get($key);
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        $full = trim((string)Session::get('user.first_name') . ' ' . (string)Session::get('user.last_name'));
        if ($full !== '') {
            return $full;
        }
        $email = Session::get('user.email');

        return is_string($email) && $email !== '' ? $email : null;
    }

    private static function appName(int $appId): ?string
    {
        try {
            $info = \DreamFactory\Core\Models\App::getCachedInfo($appId);
            $name = is_array($info) ? ($info['name'] ?? null) : null;

            return is_string($name) && $name !== '' ? $name : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** @param \Illuminate\Http\Request|null $request */
    private static function header($request, string $name): ?string
    {
        if ($request === null) {
            return null;
        }
        try {
            $value = $request->headers->get($name);
        } catch (\Throwable $e) {
            return null;
        }
        $value = is_string($value) ? trim($value) : '';

        return $value === '' ? null : $value;
    }

    private static function intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '' || $value === false) {
            return null;
        }

        return is_numeric($value) ? (int)$value : null;
    }
}

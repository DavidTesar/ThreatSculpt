/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Produced from apps/web/openapi.json, which is FastAPI's own schema for the
 * control plane, by:
 *
 *     npm run openapi          # = openapi:dump && openapi:types
 *
 * Every edit here is discarded by the next run, and CI fails the build when this
 * file differs from what regeneration produces. If a shape here looks wrong, it is
 * wrong in the control plane's Pydantic models — fix it there.
 *
 * Consume it through the aliases in src/types/domain.ts rather than reaching into
 * components['schemas'] from feature code.
 */

export interface paths {
  '/api/v1/agent/enroll': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Trade a one-time enrollment token for an API key
     * @description Unauthenticated by construction — the token *is* the credential.
     *
     *     Rate-limited per IP like the other credential-exchange endpoints, so a
     *     stolen-token guessing loop is bounded even though every guess fails.
     */
    post: operations['enroll_api_v1_agent_enroll_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agent/heartbeat': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Report liveness and collect the current allowlist
     * @description Updates ``last_seen_at`` and hands back the effective allowlist.
     *
     *     ``revoked`` is always false here: a revoked key never authenticates, so a
     *     revoked agent gets the 401 that §6 already defines as "wipe the key and
     *     exit". Returning the field keeps the documented response shape.
     */
    post: operations['heartbeat_api_v1_agent_heartbeat_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agent/jobs/claim': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Claim queued scan jobs
     * @description ``FOR UPDATE SKIP LOCKED`` — see ``scanning.sql.CLAIM_JOBS``.
     */
    post: operations['claim_api_v1_agent_jobs_claim_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agent/jobs/{job_id}/reject': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Refuse a job whose target is outside the agent's local allowlist
     * @description §4. Always audited: the agent and the control plane disagreeing about what
     *     may be scanned is the single most interesting event in this protocol.
     */
    post: operations['reject_api_v1_agent_jobs__job_id__reject_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agent/jobs/{job_id}/results': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Submit scan observations
     * @description The body is read through a size cap rather than declared as a parameter.
     *
     *     FastAPI would buffer the whole request before this function ran, which is the
     *     one thing the 10 MB cap in §5 exists to prevent.
     */
    post: operations['submit_results_api_v1_agent_jobs__job_id__results_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agent/jobs/{job_id}/status': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /** Report scan progress */
    post: operations['report_status_api_v1_agent_jobs__job_id__status_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agents': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** List agents */
    get: operations['list_agents_api_v1_agents_get'];
    put?: never;
    /**
     * Issue a one-time enrollment token
     * @description The token is returned once. Nothing can retrieve it again.
     */
    post: operations['create_enrollment_token_api_v1_agents_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agents/{agent_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Fetch an agent */
    get: operations['get_agent_api_v1_agents__agent_id__get'];
    put?: never;
    post?: never;
    /**
     * Revoke an agent
     * @description Revocation is a status change, not a delete.
     *
     *     The agent's scan history has to keep pointing at something, and "which
     *     scanner produced this result" is exactly the question an incident asks. The
     *     key stops authenticating immediately — ``find_agent_by_key_hash`` filters on
     *     ``status = 'active'`` — so a revoked agent is locked out on its next call.
     */
    delete: operations['revoke_agent_api_v1_agents__agent_id__delete'];
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/agents/{agent_id}/allowlist': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    /**
     * Narrow an agent to a subset of the authorized networks
     * @description Store the **effective** list, not the submitted one.
     *
     *     The narrowing itself was always correct — ``agents.allowlist`` may only ever
     *     subtract from the org's authorized networks, and ``effective_allowlist``
     *     enforces that on every heartbeat. What was wrong was the record of it. The
     *     submitted list was stored verbatim, so ``GET /agents/{id}`` reported
     *     ``['0.0.0.0/0', '8.8.8.0/24', '10.1.0.0/16']`` while the agent was being sent
     *     ``['10.1.0.0/16']`` — an operator reading the API during an incident would
     *     have concluded the scanner was pointed at the internet. Narrowing before the
     *     write makes the stored value the value that is in force.
     *
     *     A request whose entries all fall outside the authorized networks is refused
     *     rather than stored empty. Empty means *no per-agent restriction*, which
     *     widens the agent to every authorized network — the exact opposite of what
     *     somebody submitting a list of ranges intended. Clearing the restriction is
     *     still available, by sending an empty list explicitly.
     */
    patch: operations['update_allowlist_api_v1_agents__agent_id__allowlist_patch'];
    trace?: never;
  };
  '/api/v1/assets': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** List assets */
    get: operations['list_all_api_v1_assets_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/assets/{asset_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Fetch an asset */
    get: operations['get_one_api_v1_assets__asset_id__get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    /** Correct asset details */
    patch: operations['update_one_api_v1_assets__asset_id__patch'];
    trace?: never;
  };
  '/api/v1/assets/{asset_id}/services': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    /**
     * Map an asset to business services
     * @description Replaces the mapping wholesale, then re-scores the asset's findings.
     */
    put: operations['set_services_api_v1_assets__asset_id__services_put'];
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/auth/login': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /** Exchange a password for an access token and a refresh cookie */
    post: operations['login_api_v1_auth_login_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/auth/logout': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Revoke the refresh token family
     * @description Always succeeds. Logging out is not an operation worth an error path.
     */
    post: operations['logout_api_v1_auth_logout_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/auth/me': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** The authenticated user, their org, and their role */
    get: operations['me_api_v1_auth_me_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/auth/refresh': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Rotate the refresh token and mint a new access token
     * @description The refresh token comes from the cookie only — never from the body.
     *
     *     Accepting it in a body would make it readable by script on any page that
     *     could be tricked into echoing it, which is the whole reason it is HttpOnly.
     */
    post: operations['refresh_api_v1_auth_refresh_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/auth/register': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /** Create an organisation and its owner user */
    post: operations['register_api_v1_auth_register_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/auth/verify-email': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Prove control of the address an account was registered with
     * @description Unauthenticated: the token *is* the credential, and it names its own account.
     *
     *     Until this succeeds the account cannot be logged into and does not occupy one
     *     of the address's slots, so registering an address somebody else owns takes
     *     nothing from them.
     */
    post: operations['verify_email_api_v1_auth_verify_email_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/auth/verify-email/resend': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Re-issue the verification token for your own account
     * @description Authenticated, and only ever for the caller's own address.
     *
     *     Sending to an address named in the request would make this an open relay
     *     pointed at whoever the caller chose.
     */
    post: operations['resend_verification_api_v1_auth_verify_email_resend_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/business-services': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** List services */
    get: operations['list_services_api_v1_business_services_get'];
    put?: never;
    /** Define a business service */
    post: operations['create_service_api_v1_business_services_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/business-services/{service_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Fetch a service */
    get: operations['get_service_api_v1_business_services__service_id__get'];
    put?: never;
    post?: never;
    /** Delete a service */
    delete: operations['delete_service_api_v1_business_services__service_id__delete'];
    options?: never;
    head?: never;
    /** Update a service */
    patch: operations['update_service_api_v1_business_services__service_id__patch'];
    trace?: never;
  };
  '/api/v1/dashboard/attack-surface': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Asset and business-service graph, capped */
    get: operations['surface_api_v1_dashboard_attack_surface_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/dashboard/executive': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /**
     * Business-impact summary for a non-technical audience
     * @description Services at risk are ordered by business impact, not by CVSS.
     */
    get: operations['executive_api_v1_dashboard_executive_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/findings': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /**
     * List findings
     * @description Sorted by ``business_risk_score`` descending. That ordering is the product.
     */
    get: operations['list_all_api_v1_findings_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/findings/{finding_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Fetch a finding and the explanation of its score */
    get: operations['get_one_api_v1_findings__finding_id__get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    /**
     * Change a finding's triage status
     * @description Status transitions only. The score is computed and is not patchable.
     */
    patch: operations['update_status_api_v1_findings__finding_id__patch'];
    trace?: never;
  };
  '/api/v1/networks': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** List networks */
    get: operations['list_networks_api_v1_networks_get'];
    put?: never;
    /**
     * Register a network
     * @description Public address space needs a written assertion; RFC1918 does not.
     */
    post: operations['create_network_api_v1_networks_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/networks/{network_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Fetch a network */
    get: operations['get_network_api_v1_networks__network_id__get'];
    put?: never;
    post?: never;
    /**
     * Delete a network
     * @description Destructive, so ``admin`` or above. v1 let an unauthenticated caller do this.
     *
     *     Deleting a network is the bluntest form of withdrawing authorisation, so the
     *     same re-validation runs. ``scan_jobs.network_id`` is ``ON DELETE SET NULL``,
     *     which means the job survives the delete with its ``target`` intact — without
     *     this pass it would survive as an orphan nobody had authorised and still be
     *     dispatched on the next poll.
     */
    delete: operations['delete_network_api_v1_networks__network_id__delete'];
    options?: never;
    head?: never;
    /**
     * Update a network
     * @description Re-validates the org's open scan jobs afterwards, always.
     *
     *     Whether this edit removed coverage is a question about CIDR arithmetic across
     *     every one of the org's networks, and answering it here would be a second
     *     implementation of the rule that could disagree with the first. So the edit
     *     lands and ``revalidate_open_jobs`` re-asks the only question that matters —
     *     is each open job's target still inside *some* authorized network — which is
     *     correct for a withdrawal, a no-op for a rename, and correct for the case
     *     where a wider network still covers the target.
     */
    patch: operations['update_network_api_v1_networks__network_id__patch'];
    trace?: never;
  };
  '/api/v1/reports': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** List reports */
    get: operations['list_reports_api_v1_reports_get'];
    put?: never;
    /**
     * Request a report
     * @description 202 and a report id. The render happens on the event loop, not here.
     *
     *     Three things happen before a row is created, all of them cheap and all of
     *     them there because a render is not: an identical request already queued is
     *     returned as-is rather than rendered twice, an org past its concurrent-render
     *     ceiling is refused with 429, and this org's expired artifacts are purged.
     *     See ``reports.intake`` for the measurements that motivated each.
     */
    post: operations['request_report_api_v1_reports_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/reports/{report_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Poll a report */
    get: operations['get_report_api_v1_reports__report_id__get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/reports/{report_id}/download': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /**
     * Download a report via a signed URL
     * @description No bearer token: the signature is the credential, and it names the org.
     *
     *     The org comes out of the *signature*, never out of the request, so this is
     *     still the rule docs/API.md sets — the tenant is never a client-supplied
     *     parameter. A tampered ``report_id`` is scoped to the signed org and 404s.
     */
    get: operations['download_report_api_v1_reports__report_id__download_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/reports/{report_id}/link': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /**
     * Mint a short-lived signed download URL
     * @description Minting requires a normal authenticated session; the URL itself does not.
     */
    get: operations['download_link_api_v1_reports__report_id__link_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/scans': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** List scan jobs */
    get: operations['list_scans_api_v1_scans_get'];
    put?: never;
    /**
     * Queue a scan
     * @description Refused with ``network_not_authorized`` unless an authorized network
     *     covers the target. This is the control plane's half of the two-sided check in
     *     docs/ARCHITECTURE.md; the agent re-checks against its own local allowlist.
     */
    post: operations['create_scan_api_v1_scans_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/scans/{scan_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Fetch a scan job */
    get: operations['get_scan_api_v1_scans__scan_id__get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/scans/{scan_id}/cancel': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /** Cancel a scan job that has not finished */
    post: operations['cancel_scan_api_v1_scans__scan_id__cancel_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/users': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** List users in your org */
    get: operations['list_users_api_v1_users_get'];
    put?: never;
    /**
     * Add a user to your org
     * @description The new account starts unverified — an admin's word is not proof either.
     */
    post: operations['create_user_api_v1_users_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/users/me/password': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Change your own password
     * @description Any role. Requires the current password and ends every existing session.
     */
    post: operations['change_own_password_api_v1_users_me_password_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/users/{user_id}': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    post?: never;
    /**
     * Deactivate a user
     * @description Deactivation, not deletion — the audit trail must keep naming this user.
     */
    delete: operations['deactivate_user_api_v1_users__user_id__delete'];
    options?: never;
    head?: never;
    /** Update a user */
    patch: operations['update_user_api_v1_users__user_id__patch'];
    trace?: never;
  };
  '/api/v1/users/{user_id}/password-reset': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Issue a temporary password for a user
     * @description The operator's recovery lever: also clears any failed-login lockout.
     *
     *     The temporary password is in this response and nowhere else — it is never
     *     logged, never stored in plaintext, and not recoverable if lost.
     */
    post: operations['reset_password_api_v1_users__user_id__password_reset_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/api/v1/users/{user_id}/unlock': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    get?: never;
    put?: never;
    /**
     * Clear a failed-login lockout
     * @description The cheaper half of the recovery lever, for a lockout somebody else caused.
     *
     *     A lockout any stranger who knows the address can trigger has to be
     *     clearable without also invalidating the password the account holder still
     *     knows perfectly well.
     */
    post: operations['unlock_user_api_v1_users__user_id__unlock_post'];
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/health': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /** Liveness */
    get: operations['health_health_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
  '/ready': {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    /**
     * Readiness
     * @description 503 when the database is unreachable, so a rolling deploy waits.
     */
    get: operations['ready_ready_get'];
    put?: never;
    post?: never;
    delete?: never;
    options?: never;
    head?: never;
    patch?: never;
    trace?: never;
  };
}
export type webhooks = Record<string, never>;
export interface components {
  schemas: {
    /**
     * AgentAllowlistUpdate
     * @description Narrow one agent to a subset of the org's authorized networks.
     */
    AgentAllowlistUpdate: {
      /** Allowlist */
      allowlist: string[];
    };
    /**
     * AgentOut
     * @description Agent as an operator sees it. No key material, only the display prefix.
     */
    AgentOut: {
      /** Allowlist */
      allowlist: string[];
      /**
       * Created At
       * Format: date-time
       */
      created_at: string;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Key Prefix */
      key_prefix: string;
      /** Last Seen At */
      last_seen_at: string | null;
      /** Name */
      name: string;
      /** Status */
      status: string;
      /**
       * Updated At
       * Format: date-time
       */
      updated_at: string;
      /** Version */
      version: string | null;
    };
    /** AssetOut */
    AssetOut: {
      exposure: components['schemas']['Exposure'];
      /** First Seen At */
      first_seen_at?: string | null;
      /** Hostname */
      hostname?: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Ip */
      ip: string;
      /** Last Seen At */
      last_seen_at?: string | null;
      /** Mac */
      mac?: string | null;
      /** Network Id */
      network_id?: string | null;
      /**
       * Open Findings
       * @default 0
       */
      open_findings: number;
      /** Os Family */
      os_family?: string | null;
      /** Os Version */
      os_version?: string | null;
      /** Services */
      services?: components['schemas']['ServiceLink'][];
      /** Worst Finding Score */
      worst_finding_score?: string | null;
    };
    /**
     * AssetServicesUpdate
     * @description Full replacement of the asset -> business service mapping.
     *
     *     PUT rather than PATCH because partial mapping updates are ambiguous: an
     *     operator sending one id almost always means "this is the list", and a
     *     dropped mapping silently keeping a stale criticality would misprice every
     *     finding on the host.
     */
    AssetServicesUpdate: {
      /** Service Ids */
      service_ids: string[];
    };
    /** AssetSummary */
    AssetSummary: {
      /** Exposure */
      exposure: string;
      /** Hostname */
      hostname?: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Ip */
      ip: string;
    };
    /**
     * AssetUpdate
     * @description Operator corrections to what a scan inferred.
     *
     *     ``ip`` is absent on purpose: it is the asset's identity and is unique per
     *     org, so changing it is creating a different asset.
     */
    AssetUpdate: {
      exposure?: components['schemas']['Exposure'] | null;
      /** Hostname */
      hostname?: string | null;
      /** Network Id */
      network_id?: string | null;
      /** Os Family */
      os_family?: string | null;
      /** Os Version */
      os_version?: string | null;
    };
    /** AttackSurface */
    AttackSurface: {
      /**
       * Aggregated
       * @default false
       */
      aggregated: boolean;
      /** Edges */
      edges?: components['schemas']['GraphEdge'][];
      /**
       * Node Cap
       * @default 0
       */
      node_cap: number;
      /** Nodes */
      nodes?: components['schemas']['GraphNode'][];
      /**
       * Total Assets
       * @default 0
       */
      total_assets: number;
    };
    /** BusinessServiceCreate */
    BusinessServiceCreate: {
      criticality: components['schemas']['Criticality'];
      /** Description */
      description?: string | null;
      /** Name */
      name: string;
      /** Owner Email */
      owner_email?: string | null;
      /** Owner Name */
      owner_name?: string | null;
      /** Revenue At Risk */
      revenue_at_risk?: number | string | null;
    };
    /** BusinessServiceOut */
    BusinessServiceOut: {
      /**
       * Created At
       * Format: date-time
       */
      created_at: string;
      /** Criticality */
      criticality: string;
      /** Description */
      description: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Name */
      name: string;
      /** Owner Email */
      owner_email: string | null;
      /** Owner Name */
      owner_name: string | null;
      /** Revenue At Risk */
      revenue_at_risk: string | null;
      /**
       * Updated At
       * Format: date-time
       */
      updated_at: string;
    };
    /** BusinessServiceUpdate */
    BusinessServiceUpdate: {
      criticality?: components['schemas']['Criticality'] | null;
      /** Description */
      description?: string | null;
      /** Name */
      name?: string | null;
      /** Owner Email */
      owner_email?: string | null;
      /** Owner Name */
      owner_name?: string | null;
      /** Revenue At Risk */
      revenue_at_risk?: number | string | null;
    };
    /** ClaimRequest */
    ClaimRequest: {
      /**
       * Capacity
       * @default 1
       */
      capacity: number;
    };
    /** ClaimResponse */
    ClaimResponse: {
      /** Jobs */
      jobs: components['schemas']['ClaimedJob'][];
    };
    /** ClaimedJob */
    ClaimedJob: {
      /**
       * Job Id
       * Format: uuid
       */
      job_id: string;
      /**
       * Lease Expires At
       * Format: date-time
       */
      lease_expires_at: string;
      /** Profile */
      profile: string;
      /** Target */
      target: string;
    };
    /**
     * Criticality
     * @enum {string}
     */
    Criticality: 'critical' | 'high' | 'medium' | 'low';
    /** CveSummary */
    CveSummary: {
      /** Cve Id */
      cve_id: string;
      /** Cvss Base */
      cvss_base?: string | null;
      /**
       * Exploit Maturity
       * @default none
       */
      exploit_maturity: string;
      /** Kev Due Date */
      kev_due_date?: unknown | null;
      /**
       * Kev Listed
       * @default false
       */
      kev_listed: boolean;
      /** Severity */
      severity?: string | null;
    };
    /**
     * EnrollRequest
     * @description docs/AGENT-PROTOCOL.md §1. Unauthenticated — the token is the credential.
     */
    EnrollRequest: {
      /** Enrollment Token */
      enrollment_token: string;
      /** Hostname */
      hostname?: string | null;
      /** Name */
      name: string;
      /** Version */
      version?: string | null;
    };
    /**
     * EnrollResponse
     * @description ``api_key`` is shown here and never again.
     */
    EnrollResponse: {
      /**
       * Agent Id
       * Format: uuid
       */
      agent_id: string;
      /** Allowlist */
      allowlist: string[];
      /** Api Key */
      api_key: string;
      /**
       * Org Id
       * Format: uuid
       */
      org_id: string;
      /** Poll Interval Seconds */
      poll_interval_seconds: number;
    };
    /**
     * EnrollmentTokenCreate
     * @description ``POST /agents``. Issues a token; the agent row appears when it is used.
     *
     *     ``allowlist`` is a *note* for the operator's own records at this stage — the
     *     agent's ranges are set on its row once it enrols. Kept out of this model
     *     entirely rather than accepted and ignored.
     */
    EnrollmentTokenCreate: {
      /** Note */
      note?: string | null;
    };
    /**
     * EnrollmentTokenOut
     * @description Shown once, at creation.
     */
    EnrollmentTokenOut: {
      /** Enrollment Token */
      enrollment_token: string;
      /**
       * Expires At
       * Format: date-time
       */
      expires_at: string;
    };
    /** Envelope[AgentOut] */
    Envelope_AgentOut_: {
      data?: components['schemas']['AgentOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[AssetOut] */
    Envelope_AssetOut_: {
      data?: components['schemas']['AssetOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[AttackSurface] */
    Envelope_AttackSurface_: {
      data?: components['schemas']['AttackSurface'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[BusinessServiceOut] */
    Envelope_BusinessServiceOut_: {
      data?: components['schemas']['BusinessServiceOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ClaimResponse] */
    Envelope_ClaimResponse_: {
      data?: components['schemas']['ClaimResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[EnrollResponse] */
    Envelope_EnrollResponse_: {
      data?: components['schemas']['EnrollResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[EnrollmentTokenOut] */
    Envelope_EnrollmentTokenOut_: {
      data?: components['schemas']['EnrollmentTokenOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ExecutiveDashboard] */
    Envelope_ExecutiveDashboard_: {
      data?: components['schemas']['ExecutiveDashboard'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[FindingDetail] */
    Envelope_FindingDetail_: {
      data?: components['schemas']['FindingDetail'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[HealthOut] */
    Envelope_HealthOut_: {
      data?: components['schemas']['HealthOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[HeartbeatResponse] */
    Envelope_HeartbeatResponse_: {
      data?: components['schemas']['HeartbeatResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[JobStateResponse] */
    Envelope_JobStateResponse_: {
      data?: components['schemas']['JobStateResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[LogoutResponse] */
    Envelope_LogoutResponse_: {
      data?: components['schemas']['LogoutResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[MeResponse] */
    Envelope_MeResponse_: {
      data?: components['schemas']['MeResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[NetworkOut] */
    Envelope_NetworkOut_: {
      data?: components['schemas']['NetworkOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[NoneType] */
    Envelope_NoneType_: {
      /** Data */
      data?: null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[PasswordResetResponse] */
    Envelope_PasswordResetResponse_: {
      data?: components['schemas']['PasswordResetResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ReadinessOut] */
    Envelope_ReadinessOut_: {
      data?: components['schemas']['ReadinessOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[RegisterResponse] */
    Envelope_RegisterResponse_: {
      data?: components['schemas']['RegisterResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ReportCreated] */
    Envelope_ReportCreated_: {
      data?: components['schemas']['ReportCreated'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ReportDownloadLink] */
    Envelope_ReportDownloadLink_: {
      data?: components['schemas']['ReportDownloadLink'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ReportOut] */
    Envelope_ReportOut_: {
      data?: components['schemas']['ReportOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ResultsResponse] */
    Envelope_ResultsResponse_: {
      data?: components['schemas']['ResultsResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[ScanJobOut] */
    Envelope_ScanJobOut_: {
      data?: components['schemas']['ScanJobOut'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[TokenResponse] */
    Envelope_TokenResponse_: {
      data?: components['schemas']['TokenResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[UserAdminSummary] */
    Envelope_UserAdminSummary_: {
      data?: components['schemas']['UserAdminSummary'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[VerificationStateResponse] */
    Envelope_VerificationStateResponse_: {
      data?: components['schemas']['VerificationStateResponse'] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[AgentOut]] */
    Envelope_list_AgentOut__: {
      /** Data */
      data?: components['schemas']['AgentOut'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[AssetOut]] */
    Envelope_list_AssetOut__: {
      /** Data */
      data?: components['schemas']['AssetOut'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[BusinessServiceOut]] */
    Envelope_list_BusinessServiceOut__: {
      /** Data */
      data?: components['schemas']['BusinessServiceOut'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[FindingOut]] */
    Envelope_list_FindingOut__: {
      /** Data */
      data?: components['schemas']['FindingOut'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[NetworkOut]] */
    Envelope_list_NetworkOut__: {
      /** Data */
      data?: components['schemas']['NetworkOut'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[ReportOut]] */
    Envelope_list_ReportOut__: {
      /** Data */
      data?: components['schemas']['ReportOut'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[ScanJobOut]] */
    Envelope_list_ScanJobOut__: {
      /** Data */
      data?: components['schemas']['ScanJobOut'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** Envelope[list[UserAdminSummary]] */
    Envelope_list_UserAdminSummary__: {
      /** Data */
      data?: components['schemas']['UserAdminSummary'][] | null;
      error?: components['schemas']['ErrorBody'] | null;
      meta?: components['schemas']['PageMeta'] | null;
    };
    /** ErrorBody */
    ErrorBody: {
      /** Code */
      code: string;
      /** Field */
      field?: string | null;
      /** Message */
      message: string;
    };
    /** ExecutiveDashboard */
    ExecutiveDashboard: {
      exposure_summary: components['schemas']['ExposureSummary'];
      /**
       * Kev Findings
       * @default 0
       */
      kev_findings: number;
      remediation_progress: components['schemas']['RemediationProgress'];
      risk_posture: components['schemas']['RiskPosture'];
      /** Services At Risk */
      services_at_risk?: components['schemas']['ServiceAtRisk'][];
    };
    /**
     * Exposure
     * @enum {string}
     */
    Exposure: 'internet' | 'dmz' | 'internal' | 'isolated';
    /** ExposureSummary */
    ExposureSummary: {
      /**
       * Dmz
       * @default 0
       */
      dmz: number;
      /**
       * Internal
       * @default 0
       */
      internal: number;
      /**
       * Internet
       * @default 0
       */
      internet: number;
      /**
       * Isolated
       * @default 0
       */
      isolated: number;
    };
    /**
     * FindingDetail
     * @description Adds the score explanation and the CVE text.
     *
     *     ``score_factors`` is the reason this endpoint exists in this shape. A list
     *     row can carry a number; a detail view has to be able to defend it.
     */
    FindingDetail: {
      asset: components['schemas']['AssetSummary'];
      /** Business Risk Score */
      business_risk_score: string;
      cve: components['schemas']['CveSummary'];
      /** Description */
      description?: string | null;
      /** First Seen At */
      first_seen_at?: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Last Seen At */
      last_seen_at?: string | null;
      match: components['schemas']['MatchSummary'];
      /** Port Id */
      port_id?: string | null;
      /** Resolved At */
      resolved_at?: string | null;
      /** Scan Job Id */
      scan_job_id?: string | null;
      /** Score Factors */
      score_factors?: {
        [key: string]: unknown;
      };
      /** Services Affected */
      services_affected?: string[];
      status: components['schemas']['FindingStatus'];
    };
    /** FindingOut */
    FindingOut: {
      asset: components['schemas']['AssetSummary'];
      /** Business Risk Score */
      business_risk_score: string;
      cve: components['schemas']['CveSummary'];
      /** First Seen At */
      first_seen_at?: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Last Seen At */
      last_seen_at?: string | null;
      match: components['schemas']['MatchSummary'];
      /** Port Id */
      port_id?: string | null;
      /** Resolved At */
      resolved_at?: string | null;
      /** Scan Job Id */
      scan_job_id?: string | null;
      status: components['schemas']['FindingStatus'];
    };
    /**
     * FindingStatus
     * @enum {string}
     */
    FindingStatus: 'open' | 'accepted_risk' | 'remediated' | 'false_positive';
    /**
     * FindingStatusUpdate
     * @description Status transitions only — no other field is patchable.
     *
     *     Letting a caller PATCH ``business_risk_score`` would make the score an
     *     opinion rather than a computation, and the whole product rests on it being
     *     a computation.
     */
    FindingStatusUpdate: {
      /** Note */
      note?: string | null;
      status: components['schemas']['FindingStatus'];
    };
    /** GraphEdge */
    GraphEdge: {
      /** Source */
      source: string;
      /** Target */
      target: string;
      /** Type */
      type: string;
    };
    /** GraphNode */
    GraphNode: {
      /** Criticality */
      criticality?: string | null;
      /** Exposure */
      exposure?: string | null;
      /** Id */
      id: string;
      /** Label */
      label: string;
      /** Represents */
      represents?: number | null;
      /** Type */
      type: string;
      /**
       * Weight
       * @default 0
       */
      weight: string;
    };
    /** HTTPValidationError */
    HTTPValidationError: {
      /** Detail */
      detail?: components['schemas']['ValidationError'][];
    };
    /** HealthOut */
    HealthOut: {
      /** Environment */
      environment: string;
      /** Status */
      status: string;
    };
    /** HeartbeatRequest */
    HeartbeatRequest: {
      /**
       * Healthy
       * @default true
       */
      healthy: boolean;
      /** Nmap Version */
      nmap_version?: string | null;
      /** Version */
      version?: string | null;
    };
    /**
     * HeartbeatResponse
     * @description How allowlist changes reach the fleet, per §2.
     *
     *     ``revoked`` is always ``false`` when it is returned at all: a revoked key
     *     fails authentication and gets the 401 that §6 already tells the agent to
     *     treat as "wipe the key and exit". The field is kept because the protocol
     *     declares it and an agent may branch on it.
     */
    HeartbeatResponse: {
      /** Allowlist */
      allowlist: string[];
      /** Poll Interval Seconds */
      poll_interval_seconds: number;
      /**
       * Revoked
       * @default false
       */
      revoked: boolean;
    };
    /**
     * JobRejectRequest
     * @description §4. The agent refusing a target is expected behaviour, not an error.
     */
    JobRejectRequest: {
      /** Detail */
      detail?: string | null;
      /** Reason */
      reason: string;
    };
    /** JobStateResponse */
    JobStateResponse: {
      /** Attempts */
      attempts: number;
      /**
       * Job Id
       * Format: uuid
       */
      job_id: string;
      /** Status */
      status: string;
    };
    /**
     * JobStatusUpdate
     * @description §5 progress. ``completed`` is not accepted here — results submission is
     *     what completes a job, so a job cannot be marked done without its data.
     */
    JobStatusUpdate: {
      /** Detail */
      detail?: string | null;
      /** Progress Percent */
      progress_percent?: number | null;
      status: components['schemas']['ScanStatus'];
    };
    /**
     * LoginRequest
     * @description ``org_slug`` is optional and *only* disambiguates.
     *
     *     An address may legitimately exist in two customers, since ``users`` is
     *     unique on ``(org_id, email)``. Supplying the slug narrows the candidate set;
     *     omitting it still works, because the password is verified against each
     *     candidate. It grants nothing on its own — it is not a tenant selector in the
     *     sense docs/API.md forbids, which is a caller naming *whose data to return*.
     */
    LoginRequest: {
      /**
       * Email
       * Format: email
       */
      email: string;
      /** Org Slug */
      org_slug?: string | null;
      /** Password */
      password: string;
    };
    /** LogoutResponse */
    LogoutResponse: {
      /** Revoked */
      revoked: boolean;
    };
    /**
     * MatchConfidence
     * @description How sure the CPE matcher was that this CVE applies to this service.
     *
     *     Persisted on the finding rather than buried in ``score_factors`` for two
     *     reasons: it survives a re-score (which rewrites the factors), and it is a
     *     filter an operator actually wants — "show me only what you are sure about"
     *     is the first question a sceptical analyst asks.
     * @enum {string}
     */
    MatchConfidence: 'high' | 'medium' | 'low';
    /**
     * MatchSummary
     * @description How the CVE was attached to this service, and how sure we were.
     *
     *     Surfaced on every finding rather than only on request: an operator deciding
     *     whether to page someone at 2am needs to know the difference between "your
     *     version is inside the affected range" and "we guessed from a banner".
     */
    MatchSummary: {
      confidence: components['schemas']['MatchConfidence'];
      /** Method */
      method?: string | null;
      /** Rationale */
      rationale?: string | null;
    };
    /** MeResponse */
    MeResponse: {
      org: components['schemas']['OrgSummary'];
      user: components['schemas']['UserSummary'];
    };
    /** NetworkCreate */
    NetworkCreate: {
      /** Authorization Note */
      authorization_note?: string | null;
      /**
       * Authorized
       * @default false
       */
      authorized: boolean;
      /** Cidr */
      cidr: string;
      /** Name */
      name: string;
    };
    /** NetworkOut */
    NetworkOut: {
      /** Authorization Note */
      authorization_note: string | null;
      /** Authorized */
      authorized: boolean;
      /** Authorized At */
      authorized_at?: string | null;
      /** Authorized By User Id */
      authorized_by_user_id?: string | null;
      /** Cidr */
      cidr: string;
      /**
       * Created At
       * Format: date-time
       */
      created_at: string;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Name */
      name: string;
      /**
       * Updated At
       * Format: date-time
       */
      updated_at: string;
    };
    /**
     * NetworkUpdate
     * @description All fields optional; ``cidr`` is immutable once assets reference it.
     */
    NetworkUpdate: {
      /** Authorization Note */
      authorization_note?: string | null;
      /** Authorized */
      authorized?: boolean | null;
      /** Name */
      name?: string | null;
    };
    /** OrgSummary */
    OrgSummary: {
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Name */
      name: string;
      /** Plan */
      plan: string;
      /** Slug */
      slug: string;
      /** Status */
      status: string;
    };
    /** PageMeta */
    PageMeta: {
      /** Page */
      page: number;
      /** Per Page */
      per_page: number;
      /** Total */
      total: number;
    };
    /**
     * PasswordChangeRequest
     * @description A user changing their own password. The current one is required.
     *
     *     Requiring it is what stops a stolen access token from becoming a permanent
     *     account takeover in one request.
     */
    PasswordChangeRequest: {
      /** Current Password */
      current_password: string;
      /** New Password */
      new_password: string;
    };
    /**
     * PasswordResetResponse
     * @description An admin-issued temporary password, shown exactly once.
     *
     *     Same handling as every other credential this service mints: the plaintext
     *     exists in this response and nowhere else, and the holder is expected to
     *     change it immediately.
     */
    PasswordResetResponse: {
      /** Sessions Revoked */
      sessions_revoked: number;
      /** Temporary Password */
      temporary_password: string;
      /**
       * User Id
       * Format: uuid
       */
      user_id: string;
    };
    /** ReadinessOut */
    ReadinessOut: {
      /** Database */
      database: string;
      /** Status */
      status: string;
    };
    /**
     * RegisterRequest
     * @description Creates an org and its first ``owner`` user. Trial plan.
     */
    RegisterRequest: {
      /**
       * Email
       * Format: email
       */
      email: string;
      /** Full Name */
      full_name?: string | null;
      /** Org Name */
      org_name: string;
      /** Org Slug */
      org_slug: string;
      /** Password */
      password: string;
    };
    /** RegisterResponse */
    RegisterResponse: {
      /** Access Token */
      access_token: string;
      /**
       * Expires At
       * Format: date-time
       */
      expires_at: string;
      org: components['schemas']['OrgSummary'];
      user: components['schemas']['UserSummary'];
    };
    /** RejectedHost */
    RejectedHost: {
      /** Ip */
      ip: string;
      /** Reason */
      reason: string;
    };
    /** RemediationProgress */
    RemediationProgress: {
      /**
       * Opened 30D
       * @default 0
       */
      opened_30d: number;
      /**
       * Resolved 30D
       * @default 0
       */
      resolved_30d: number;
    };
    /** ReportCreate */
    ReportCreate: {
      /**
       * Format
       * @default html
       */
      format: string;
      scope?: components['schemas']['ReportScope'];
      /** @default executive_summary */
      type: components['schemas']['ReportType'];
    };
    /**
     * ReportCreated
     * @description 202 body. Named ``report_id`` to match docs/API.md exactly.
     */
    ReportCreated: {
      /**
       * Report Id
       * Format: uuid
       */
      report_id: string;
      status: components['schemas']['ReportStatus'];
    };
    /** ReportDownloadLink */
    ReportDownloadLink: {
      /**
       * Expires At
       * Format: date-time
       */
      expires_at: string;
      /** Url */
      url: string;
    };
    /** ReportOut */
    ReportOut: {
      /** Byte Size */
      byte_size?: number | null;
      /**
       * Created At
       * Format: date-time
       */
      created_at: string;
      /** Error */
      error?: string | null;
      /** Format */
      format: string;
      /** Generated At */
      generated_at?: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      status: components['schemas']['ReportStatus'];
      /** Type */
      type: string;
    };
    /**
     * ReportScope
     * @description What the report should cover. Empty means the whole org.
     */
    ReportScope: {
      /** Service Ids */
      service_ids?: string[];
      /** Since */
      since?: string | null;
    };
    /**
     * ReportStatus
     * @enum {string}
     */
    ReportStatus: 'queued' | 'generating' | 'ready' | 'failed';
    /**
     * ReportType
     * @enum {string}
     */
    ReportType: 'executive_summary';
    /** ResultsResponse */
    ResultsResponse: {
      /** Accepted */
      accepted: boolean;
      /** Hosts Ingested */
      hosts_ingested: number;
      /**
       * Hosts Rejected
       * @default []
       */
      hosts_rejected: components['schemas']['RejectedHost'][];
    };
    /** RiskPosture */
    RiskPosture: {
      /** Band */
      band: string;
      /** Score */
      score: number;
      /** Trend 30D */
      trend_30d: number;
    };
    /**
     * ScanJobCreate
     * @description ``POST /scans``. A profile name, never nmap flags.
     */
    ScanJobCreate: {
      /** Network Id */
      network_id?: string | null;
      profile: components['schemas']['ScanProfile'];
      /** Target */
      target: string;
    };
    /** ScanJobOut */
    ScanJobOut: {
      /** Agent Id */
      agent_id: string | null;
      /** Attempts */
      attempts: number;
      /**
       * Created At
       * Format: date-time
       */
      created_at: string;
      /** Error */
      error: string | null;
      /** Finished At */
      finished_at: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Lease Expires At */
      lease_expires_at: string | null;
      /** Network Id */
      network_id: string | null;
      /** Profile */
      profile: string;
      /** Progress Percent */
      progress_percent: number | null;
      /** Requested By User Id */
      requested_by_user_id: string | null;
      /** Started At */
      started_at: string | null;
      /** Status */
      status: string;
      /** Target */
      target: string;
      /**
       * Updated At
       * Format: date-time
       */
      updated_at: string;
    };
    /**
     * ScanProfile
     * @description Named profiles only. The API never accepts raw nmap flags.
     * @enum {string}
     */
    ScanProfile: 'discovery' | 'service' | 'vulnerability';
    /**
     * ScanStatus
     * @enum {string}
     */
    ScanStatus: 'queued' | 'claimed' | 'running' | 'completed' | 'failed' | 'cancelled';
    /** ServiceAtRisk */
    ServiceAtRisk: {
      /** Assets Affected */
      assets_affected: number;
      /** Criticality */
      criticality: string;
      /** Name */
      name: string;
      /** Open Findings */
      open_findings: number;
      /** Revenue At Risk */
      revenue_at_risk?: string | null;
      /**
       * Service Id
       * Format: uuid
       */
      service_id: string;
      /** Worst Finding Score */
      worst_finding_score: string;
    };
    /** ServiceLink */
    ServiceLink: {
      /** Criticality */
      criticality: string;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Name */
      name: string;
    };
    /**
     * TokenResponse
     * @description The refresh token is deliberately absent — it goes out as a cookie only.
     */
    TokenResponse: {
      /** Access Token */
      access_token: string;
      /**
       * Expires At
       * Format: date-time
       */
      expires_at: string;
      /**
       * Token Type
       * @default bearer
       */
      token_type: string;
    };
    /**
     * UserAdminSummary
     * @description What an administrator needs that the user themselves does not.
     *
     *     ``locked`` is derived rather than stored: an operator looking at the user
     *     directory has to be able to see *why* a colleague cannot log in, or the
     *     unlock lever below is one they never know to pull.
     */
    UserAdminSummary: {
      /** Email */
      email: string;
      /** Full Name */
      full_name: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Last Login At */
      last_login_at: string | null;
      /** Locked */
      locked: boolean;
      /** Role */
      role: string;
      /** Status */
      status: string;
      /** Verified */
      verified: boolean;
    };
    /**
     * UserCreate
     * @description An administrator adding a colleague to their own org.
     *
     *     There is no ``org_id``: the org comes from the caller's principal, like
     *     everywhere else. ``role`` is bounded by the caller's own role at the service
     *     layer — an admin cannot mint an owner.
     */
    UserCreate: {
      /**
       * Email
       * Format: email
       */
      email: string;
      /** Full Name */
      full_name?: string | null;
      /** Password */
      password: string;
      /**
       * Role
       * @default viewer
       */
      role: string;
    };
    /** UserSummary */
    UserSummary: {
      /** Email */
      email: string;
      /** Full Name */
      full_name: string | null;
      /**
       * Id
       * Format: uuid
       */
      id: string;
      /** Last Login At */
      last_login_at: string | null;
      /** Role */
      role: string;
      /** Status */
      status: string;
    };
    /**
     * UserUpdate
     * @description Partial update. Only the fields actually sent are applied.
     */
    UserUpdate: {
      /** Full Name */
      full_name?: string | null;
      /** Role */
      role?: string | null;
      /** Status */
      status?: string | null;
    };
    /** ValidationError */
    ValidationError: {
      /** Context */
      ctx?: Record<string, never>;
      /** Input */
      input?: unknown;
      /** Location */
      loc: (string | number)[];
      /** Message */
      msg: string;
      /** Error Type */
      type: string;
    };
    /**
     * VerificationStateResponse
     * @description Whether the address is proved, and when the outstanding claim lapses.
     */
    VerificationStateResponse: {
      /** Email */
      email: string;
      /** Verification Expires At */
      verification_expires_at: string | null;
      /** Verified */
      verified: boolean;
    };
    /**
     * VerifyEmailRequest
     * @description The token from the verification message. No address, no org.
     *
     *     Naming the account would let a caller aim a guessed token at a chosen
     *     victim; the token identifies the account by itself or it is worthless.
     */
    VerifyEmailRequest: {
      /** Token */
      token: string;
    };
  };
  responses: never;
  parameters: never;
  requestBodies: never;
  headers: never;
  pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
  enroll_api_v1_agent_enroll_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['EnrollRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      201: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_EnrollResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  heartbeat_api_v1_agent_heartbeat_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['HeartbeatRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_HeartbeatResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  claim_api_v1_agent_jobs_claim_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['ClaimRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ClaimResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  reject_api_v1_agent_jobs__job_id__reject_post: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Scan job id within your organisation */
        job_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['JobRejectRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_JobStateResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  submit_results_api_v1_agent_jobs__job_id__results_post: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Scan job id within your organisation */
        job_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      202: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ResultsResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  report_status_api_v1_agent_jobs__job_id__status_post: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Scan job id within your organisation */
        job_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['JobStatusUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_JobStateResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  list_agents_api_v1_agents_get: {
    parameters: {
      query?: {
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_AgentOut__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  create_enrollment_token_api_v1_agents_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['EnrollmentTokenCreate'];
      };
    };
    responses: {
      /** @description Successful Response */
      201: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_EnrollmentTokenOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  get_agent_api_v1_agents__agent_id__get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Agent id within your organisation */
        agent_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_AgentOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  revoke_agent_api_v1_agents__agent_id__delete: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Agent id within your organisation */
        agent_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_AgentOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  update_allowlist_api_v1_agents__agent_id__allowlist_patch: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Agent id within your organisation */
        agent_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['AgentAllowlistUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_AgentOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  list_all_api_v1_assets_get: {
    parameters: {
      query?: {
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
        /** @description Registered network */
        network_id?: string | null;
        /** @description Network exposure tier */
        exposure?: components['schemas']['Exposure'] | null;
        /** @description Business service supported */
        service_id?: string | null;
        /** @description Hostname or IP substring */
        q?: string | null;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_AssetOut__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  get_one_api_v1_assets__asset_id__get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Asset id within your organisation */
        asset_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_AssetOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  update_one_api_v1_assets__asset_id__patch: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Asset id within your organisation */
        asset_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['AssetUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_AssetOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  set_services_api_v1_assets__asset_id__services_put: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Asset id within your organisation */
        asset_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['AssetServicesUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_AssetOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  login_api_v1_auth_login_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['LoginRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_TokenResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  logout_api_v1_auth_logout_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_LogoutResponse_'];
        };
      };
    };
  };
  me_api_v1_auth_me_get: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_MeResponse_'];
        };
      };
    };
  };
  refresh_api_v1_auth_refresh_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_TokenResponse_'];
        };
      };
    };
  };
  register_api_v1_auth_register_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['RegisterRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      201: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_RegisterResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  verify_email_api_v1_auth_verify_email_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['VerifyEmailRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_VerificationStateResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  resend_verification_api_v1_auth_verify_email_resend_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_VerificationStateResponse_'];
        };
      };
    };
  };
  list_services_api_v1_business_services_get: {
    parameters: {
      query?: {
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_BusinessServiceOut__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  create_service_api_v1_business_services_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['BusinessServiceCreate'];
      };
    };
    responses: {
      /** @description Successful Response */
      201: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_BusinessServiceOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  get_service_api_v1_business_services__service_id__get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Business service id within your organisation */
        service_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_BusinessServiceOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  delete_service_api_v1_business_services__service_id__delete: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Business service id within your organisation */
        service_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_NoneType_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  update_service_api_v1_business_services__service_id__patch: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Business service id within your organisation */
        service_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['BusinessServiceUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_BusinessServiceOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  surface_api_v1_dashboard_attack_surface_get: {
    parameters: {
      query?: {
        /** @description Maximum nodes to return */
        node_cap?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_AttackSurface_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  executive_api_v1_dashboard_executive_get: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ExecutiveDashboard_'];
        };
      };
    };
  };
  list_all_api_v1_findings_get: {
    parameters: {
      query?: {
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
        /** @description Triage status */
        status?: components['schemas']['FindingStatus'] | null;
        /** @description CVE severity band */
        severity?: string | null;
        /** @description Business service the asset supports */
        service_id?: string | null;
        /** @description Restrict to one asset */
        asset_id?: string | null;
        /** @description Only CISA KEV-listed CVEs */
        kev_only?: boolean;
        /** @description Minimum CPE match confidence */
        min_confidence?: components['schemas']['MatchConfidence'] | null;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_FindingOut__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  get_one_api_v1_findings__finding_id__get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Finding id within your organisation */
        finding_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_FindingDetail_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  update_status_api_v1_findings__finding_id__patch: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Finding id within your organisation */
        finding_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['FindingStatusUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_FindingDetail_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  list_networks_api_v1_networks_get: {
    parameters: {
      query?: {
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_NetworkOut__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  create_network_api_v1_networks_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['NetworkCreate'];
      };
    };
    responses: {
      /** @description Successful Response */
      201: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_NetworkOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  get_network_api_v1_networks__network_id__get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Network id within your organisation */
        network_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_NetworkOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  delete_network_api_v1_networks__network_id__delete: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Network id within your organisation */
        network_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_NoneType_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  update_network_api_v1_networks__network_id__patch: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Network id within your organisation */
        network_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['NetworkUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_NetworkOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  list_reports_api_v1_reports_get: {
    parameters: {
      query?: {
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_ReportOut__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  request_report_api_v1_reports_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['ReportCreate'];
      };
    };
    responses: {
      /** @description Successful Response */
      202: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ReportCreated_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  get_report_api_v1_reports__report_id__get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Report id within your organisation */
        report_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ReportOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  download_report_api_v1_reports__report_id__download_get: {
    parameters: {
      query: {
        /** @description Signed download token */
        token: string;
      };
      header?: never;
      path: {
        /** @description Report id within your organisation */
        report_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content?: never;
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  download_link_api_v1_reports__report_id__link_get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Report id within your organisation */
        report_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ReportDownloadLink_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  list_scans_api_v1_scans_get: {
    parameters: {
      query?: {
        /** @description Filter by job status */
        status?: components['schemas']['ScanStatus'] | null;
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_ScanJobOut__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  create_scan_api_v1_scans_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['ScanJobCreate'];
      };
    };
    responses: {
      /** @description Successful Response */
      201: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ScanJobOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  get_scan_api_v1_scans__scan_id__get: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Scan job id within your organisation */
        scan_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ScanJobOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  cancel_scan_api_v1_scans__scan_id__cancel_post: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description Scan job id within your organisation */
        scan_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ScanJobOut_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  list_users_api_v1_users_get: {
    parameters: {
      query?: {
        /** @description 1-based page number */
        page?: number;
        /** @description Items per page (max 200) */
        per_page?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_list_UserAdminSummary__'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  create_user_api_v1_users_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['UserCreate'];
      };
    };
    responses: {
      /** @description Successful Response */
      201: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_UserAdminSummary_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  change_own_password_api_v1_users_me_password_post: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['PasswordChangeRequest'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_UserAdminSummary_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  deactivate_user_api_v1_users__user_id__delete: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description User id within your organisation */
        user_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_UserAdminSummary_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  update_user_api_v1_users__user_id__patch: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description User id within your organisation */
        user_id: string;
      };
      cookie?: never;
    };
    requestBody: {
      content: {
        'application/json': components['schemas']['UserUpdate'];
      };
    };
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_UserAdminSummary_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  reset_password_api_v1_users__user_id__password_reset_post: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description User id within your organisation */
        user_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_PasswordResetResponse_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  unlock_user_api_v1_users__user_id__unlock_post: {
    parameters: {
      query?: never;
      header?: never;
      path: {
        /** @description User id within your organisation */
        user_id: string;
      };
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_UserAdminSummary_'];
        };
      };
      /** @description Validation Error */
      422: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['HTTPValidationError'];
        };
      };
    };
  };
  health_health_get: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_HealthOut_'];
        };
      };
    };
  };
  ready_ready_get: {
    parameters: {
      query?: never;
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: {
      /** @description Successful Response */
      200: {
        headers: {
          [name: string]: unknown;
        };
        content: {
          'application/json': components['schemas']['Envelope_ReadinessOut_'];
        };
      };
    };
  };
}

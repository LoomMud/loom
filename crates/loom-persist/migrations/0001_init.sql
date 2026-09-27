-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Schema owner: this migration runs as `loom_owner` (LOOM_DB_MIGRATE_URL),
-- which owns every table and function created here. The world-runtime login
-- `loom_app` is granted only the narrow privileges below; it never owns
-- anything and cannot re-grant itself rights (D-27.4).
--
-- This migration does not create Postgres logins and contains no passwords.
-- `loom_owner` and `loom_app` must already exist before `migrate()` runs
-- (CI: a setup step; staging: provisioned from /etc/loom/secrets.env,
-- OBI-42).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Defence in depth: nobody but the owner may create objects in `public`.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- object_state key per design §8.1: object_path plus a key lets one object
-- persist more than one named record (e.g. inventory sub-records) under the
-- same primary path.
CREATE TABLE object_state (
    object_path TEXT NOT NULL,
    key TEXT NOT NULL DEFAULT '',
    program_path TEXT NOT NULL,
    program_version BIGINT NOT NULL,
    schema_hash TEXT NOT NULL,
    state_json JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (object_path, key)
);

-- ---------------------------------------------------------------------------
-- Roles tables per design §5.11.3 (tier model). A player is an account with
-- no `staff` row and has no tier. Only `security definer` functions below
-- may write these tables; `loom_app` gets SELECT only.
-- ---------------------------------------------------------------------------

CREATE TABLE staff (
    uid           TEXT PRIMARY KEY,              -- stable builder id used in paths and file ownership
    account_id    UUID NOT NULL UNIQUE REFERENCES accounts(id),
    tier          SMALLINT NOT NULL CHECK (tier BETWEEN 1 AND 5),
    totp_required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE domains (
    name  TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('wip', 'live', 'archived'))
);

CREATE TABLE domain_members (
    domain TEXT NOT NULL REFERENCES domains(name),
    uid    TEXT NOT NULL REFERENCES staff(uid),
    role   TEXT NOT NULL CHECK (role IN ('member', 'lead')),
    PRIMARY KEY (domain, uid)
);

-- Seed values from design §5.11.2. NULL means "unlimited (alerted)".
CREATE TABLE tier_policy (
    tier                SMALLINT PRIMARY KEY,
    max_ticks_exec      INT,
    max_mem_exec_mb     INT,
    tick_share_per_min  BIGINT,
    max_objects         INT,
    max_heartbeats      INT,
    max_callouts_obj    INT,
    max_callouts_uid    INT,
    disk_quota_mb       INT,
    efun_classes        SMALLINT[] NOT NULL
);

CREATE TABLE grants (
    uid         TEXT NOT NULL REFERENCES staff(uid),
    kind        TEXT NOT NULL CHECK (kind IN ('efun', 'db_query', 'path')),
    target      TEXT NOT NULL,
    granted_by  TEXT NOT NULL REFERENCES staff(uid),
    expires_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (uid, kind, target)
);

-- Append-only audit trail. Every security definer function below writes here
-- in the same transaction as its change.
CREATE TABLE role_changes (
    id       BIGSERIAL PRIMARY KEY,
    uid      TEXT,
    old_tier SMALLINT,
    new_tier SMALLINT,
    domain   TEXT,
    actor    TEXT NOT NULL,
    reason   TEXT NOT NULL,
    at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tier_policy (
    tier, max_ticks_exec, max_mem_exec_mb, tick_share_per_min, max_objects,
    max_heartbeats, max_callouts_obj, max_callouts_uid, disk_quota_mb, efun_classes
) VALUES
    (1, 200000,   4,  20000000,    200,   10,   8,   100,    5,  ARRAY[0, 1]::SMALLINT[]),
    (2, 1000000,  16, 200000000,   2000,  200,  64,  1000,   50, ARRAY[0, 1]::SMALLINT[]),
    (3, 2000000,  32, 1000000000, 10000,  1000, 64,  5000,   200, ARRAY[0, 1, 2]::SMALLINT[]),
    (4, 5000000,  64, 3000000000, 50000,  5000, 64,  20000,  1024, ARRAY[0, 1, 2, 3]::SMALLINT[]),
    (5, 10000000, 128, NULL,      NULL,   NULL, 64,  NULL,   1024, ARRAY[0, 1, 2, 3, 4]::SMALLINT[])
ON CONFLICT (tier) DO NOTHING;

-- Read-only view that hides expired grants (design §5.11.2 note: expiry is
-- how grants stay exceptions, never full tier changes).
CREATE VIEW active_grants AS
SELECT uid, kind, target, granted_by, expires_at
FROM grants
WHERE expires_at > NOW();

-- ---------------------------------------------------------------------------
-- Grants: loom_app is the world-runtime login. It is not an owner and has no
-- insert/update/delete on the role tables (D-27.4).
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO loom_app;
GRANT SELECT, INSERT ON accounts TO loom_app;
GRANT SELECT, INSERT, UPDATE ON object_state TO loom_app;
GRANT SELECT ON staff TO loom_app;
GRANT SELECT ON domains TO loom_app;
GRANT SELECT ON domain_members TO loom_app;
GRANT SELECT ON tier_policy TO loom_app;
GRANT SELECT ON grants TO loom_app;
GRANT SELECT ON active_grants TO loom_app;
GRANT SELECT ON role_changes TO loom_app;

-- ---------------------------------------------------------------------------
-- Security definer functions (D-27.2). Every one of these:
--   * re-checks the §5.11.2 promotion-rights row in SQL (never trusts the
--     caller's claimed rights);
--   * writes role_changes in the same transaction;
--   * RAISEs on denial;
--   * pins search_path to pg_catalog, pg_temp and schema-qualifies every
--     object it touches (D-27.5), so a hijacked search_path in the calling
--     session cannot redirect it to an attacker-controlled shadow table.
-- ---------------------------------------------------------------------------

-- roles_set_tier: T3 (domain lead) may only promote T1 -> T2 within a domain
-- it leads. T4 (arch) may set any tier 1-3 for anyone currently below T4.
-- Neither may self-promote. T4/T5 are never granted here in Phase 1; see
-- roles_bootstrap_root for root bootstrap, and "what's next" below for the
-- deferred two-root approval flow for T4/T5 grants.
CREATE OR REPLACE FUNCTION public.roles_set_tier(
    p_actor       TEXT,
    p_target_uid  TEXT,
    p_new_tier    SMALLINT,
    p_reason      TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier SMALLINT;
    old_tier   SMALLINT;
    target_account UUID;
    actor_leads_target_domain BOOLEAN;
BEGIN
    IF p_actor IS NULL OR p_target_uid IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, target uid and reason are required';
    END IF;

    IF p_actor = p_target_uid THEN
        RAISE EXCEPTION 'self-promotion is not permitted';
    END IF;

    IF p_new_tier IS NULL OR p_new_tier < 1 OR p_new_tier > 3 THEN
        RAISE EXCEPTION 'roles_set_tier may only set tiers 1-3 in Phase 1; T4/T5 grants are deferred (see roles_bootstrap_root)';
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    SELECT tier INTO old_tier FROM public.staff WHERE uid = p_target_uid;
    old_tier := COALESCE(old_tier, 0);

    IF actor_tier >= 4 THEN
        IF old_tier >= 4 THEN
            RAISE EXCEPTION 'actor tier % may not change the tier of an arch/root account', actor_tier;
        END IF;
    ELSIF actor_tier = 3 THEN
        IF old_tier <> 1 OR p_new_tier <> 2 THEN
            RAISE EXCEPTION 'domain leads (T3) may only promote T1 to T2';
        END IF;

        SELECT EXISTS (
            SELECT 1
            FROM public.domain_members target_membership
            JOIN public.domain_members lead_membership
              ON lead_membership.domain = target_membership.domain
            WHERE target_membership.uid = p_target_uid
              AND lead_membership.uid = p_actor
              AND lead_membership.role = 'lead'
        ) INTO actor_leads_target_domain;

        IF NOT actor_leads_target_domain THEN
            RAISE EXCEPTION 'actor does not lead a domain % is a member of', p_target_uid;
        END IF;
    ELSE
        RAISE EXCEPTION 'actor tier % may not change roles', actor_tier;
    END IF;

    SELECT id INTO target_account FROM public.accounts WHERE username = p_target_uid;
    IF target_account IS NULL THEN
        RAISE EXCEPTION 'no account found for uid %', p_target_uid;
    END IF;

    INSERT INTO public.staff (uid, account_id, tier)
    VALUES (p_target_uid, target_account, p_new_tier)
    ON CONFLICT (uid) DO UPDATE SET tier = EXCLUDED.tier;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_target_uid, old_tier, p_new_tier, NULL, p_actor, p_reason);
END;
$$;

REVOKE ALL ON FUNCTION public.roles_set_tier(TEXT, TEXT, SMALLINT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.roles_set_tier(TEXT, TEXT, SMALLINT, TEXT) TO loom_app;

-- roles_set_member: T3 may add/remove members (role = 'member') in domains
-- it leads; T4 may also appoint leads (role = 'lead') in any domain.
-- p_role = NULL or 'none' removes the membership row.
CREATE OR REPLACE FUNCTION public.roles_set_member(
    p_actor      TEXT,
    p_domain     TEXT,
    p_target_uid TEXT,
    p_role       TEXT,
    p_reason     TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier SMALLINT;
    actor_leads_domain BOOLEAN;
BEGIN
    IF p_actor IS NULL OR p_domain IS NULL OR p_target_uid IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, domain, target uid and reason are required';
    END IF;

    IF p_role IS NOT NULL AND p_role NOT IN ('member', 'lead', 'none') THEN
        RAISE EXCEPTION 'invalid domain role %', p_role;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.domains WHERE name = p_domain) THEN
        RAISE EXCEPTION 'unknown domain %', p_domain;
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier >= 4 THEN
        NULL; -- arch/root may set any membership, including appointing leads
    ELSIF actor_tier = 3 THEN
        SELECT EXISTS (
            SELECT 1 FROM public.domain_members
            WHERE domain = p_domain AND uid = p_actor AND role = 'lead'
        ) INTO actor_leads_domain;

        IF NOT actor_leads_domain THEN
            RAISE EXCEPTION 'actor does not lead domain %', p_domain;
        END IF;

        IF p_role = 'lead' THEN
            RAISE EXCEPTION 'domain leads (T3) may not appoint other leads';
        END IF;
    ELSE
        RAISE EXCEPTION 'actor tier % may not change domain membership', actor_tier;
    END IF;

    IF p_role IS NULL OR p_role = 'none' THEN
        DELETE FROM public.domain_members WHERE domain = p_domain AND uid = p_target_uid;
    ELSE
        INSERT INTO public.domain_members (domain, uid, role)
        VALUES (p_domain, p_target_uid, p_role)
        ON CONFLICT (domain, uid) DO UPDATE SET role = EXCLUDED.role;
    END IF;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_target_uid, NULL, NULL, p_domain, p_actor, p_reason);
END;
$$;

REVOKE ALL ON FUNCTION public.roles_set_member(TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.roles_set_member(TEXT, TEXT, TEXT, TEXT, TEXT) TO loom_app;

-- roles_grant: per-uid exceptions (efun/db_query/path), always with an
-- expiry and a granting actor, so exceptions never require a tier change.
CREATE OR REPLACE FUNCTION public.roles_grant(
    p_actor      TEXT,
    p_uid        TEXT,
    p_kind       TEXT,
    p_target     TEXT,
    p_expires_at TIMESTAMPTZ,
    p_reason     TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier SMALLINT;
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_kind IS NULL OR p_target IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, uid, kind, target and reason are required';
    END IF;

    IF p_kind NOT IN ('efun', 'db_query', 'path') THEN
        RAISE EXCEPTION 'invalid grant kind %', p_kind;
    END IF;

    IF p_expires_at IS NULL OR p_expires_at <= NOW() THEN
        RAISE EXCEPTION 'grants must have a future expiry';
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 3 THEN
        RAISE EXCEPTION 'actor tier % may not grant per-uid exceptions', actor_tier;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.staff WHERE uid = p_uid) THEN
        RAISE EXCEPTION 'grant target % is not staff', p_uid;
    END IF;

    INSERT INTO public.grants (uid, kind, target, granted_by, expires_at)
    VALUES (p_uid, p_kind, p_target, p_actor, p_expires_at)
    ON CONFLICT (uid, kind, target) DO UPDATE
        SET granted_by = EXCLUDED.granted_by,
            expires_at = EXCLUDED.expires_at;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_uid, NULL, NULL, NULL, p_actor,
            format('grant %s:%s until %s -- %s', p_kind, p_target, p_expires_at, p_reason));
END;
$$;

REVOKE ALL ON FUNCTION public.roles_grant(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.roles_grant(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT) TO loom_app;

-- roles_revoke_grant: removes a per-uid exception before its natural expiry.
CREATE OR REPLACE FUNCTION public.roles_revoke_grant(
    p_actor  TEXT,
    p_uid    TEXT,
    p_kind   TEXT,
    p_target TEXT,
    p_reason TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier SMALLINT;
    deleted_count INTEGER;
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_kind IS NULL OR p_target IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, uid, kind, target and reason are required';
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 3 THEN
        RAISE EXCEPTION 'actor tier % may not revoke grants', actor_tier;
    END IF;

    DELETE FROM public.grants
    WHERE uid = p_uid AND kind = p_kind AND target = p_target;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    IF deleted_count = 0 THEN
        RAISE EXCEPTION 'no matching grant to revoke for %/%/%', p_uid, p_kind, p_target;
    END IF;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_uid, NULL, NULL, NULL, p_actor, format('revoke %s:%s -- %s', p_kind, p_target, p_reason));
END;
$$;

REVOKE ALL ON FUNCTION public.roles_revoke_grant(TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.roles_revoke_grant(TEXT, TEXT, TEXT, TEXT, TEXT) TO loom_app;

-- roles_bootstrap_root: owner-only root bootstrap. Deliberately NOT granted
-- to loom_app -- there is no driver-reachable path to T5. The two-root
-- approval flow for further T4/T5 grants is deferred; see "what's next"
-- in the OBI-27 PR description.
CREATE OR REPLACE FUNCTION public.roles_bootstrap_root(
    p_uid        TEXT,
    p_account_id UUID
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_uid IS NULL OR p_account_id IS NULL THEN
        RAISE EXCEPTION 'uid and account_id are required';
    END IF;

    INSERT INTO public.staff (uid, account_id, tier, totp_required)
    VALUES (p_uid, p_account_id, 5, TRUE)
    ON CONFLICT (uid) DO UPDATE SET tier = 5, totp_required = TRUE;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_uid, NULL, 5, NULL, 'roles_bootstrap_root',
            'root bootstrap (owner-invoked; not reachable via loom_app)');
END;
$$;

REVOKE ALL ON FUNCTION public.roles_bootstrap_root(TEXT, UUID) FROM PUBLIC;
-- Intentionally no GRANT EXECUTE ... TO loom_app here.

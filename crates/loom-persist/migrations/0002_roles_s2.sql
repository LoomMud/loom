-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-119 (S2a, design note OBI-36 §1, §5, §6): two-root proposals for
-- T4/T5 tier changes, the `staff.account_id` existing-staff lookup fix
-- (R2 follow-up), `NOTIFY roles_changed` on every roles table, and a
-- Postgres `audit_log` sink for the driver's in-memory decision ring.
--
-- Runs as `loom_owner`, same as 0001_init.sql. Contains no logins and no
-- passwords.

-- ---------------------------------------------------------------------------
-- §6 (D-S2.6): resolve an existing staff row by its own account_id first,
-- so a uid that no longer matches its account's username (for example a
-- root created with a uid different from its account username) keeps
-- resolving correctly. Falls back to accounts.username only for a target
-- that has no staff row yet (first-time promotion to staff).
--
-- Not a security definer itself: it runs with the privileges of whichever
-- security definer function calls it, which is always loom_owner (the
-- role context set by SECURITY DEFINER does not change for nested calls).
-- It is not reachable directly by loom_app (no EXECUTE grant below).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.roles_resolve_account(p_target_uid TEXT)
RETURNS UUID
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    existing_account UUID;
    fallback_account UUID;
BEGIN
    SELECT account_id INTO existing_account
    FROM public.staff
    WHERE uid = p_target_uid;

    IF existing_account IS NOT NULL THEN
        RETURN existing_account;
    END IF;

    SELECT id INTO fallback_account
    FROM public.accounts
    WHERE username = p_target_uid;

    IF fallback_account IS NULL THEN
        RAISE EXCEPTION 'no account found for uid %', p_target_uid;
    END IF;

    RETURN fallback_account;
END;
$$;

REVOKE ALL ON FUNCTION public.roles_resolve_account(TEXT) FROM PUBLIC;
-- Intentionally no GRANT EXECUTE ... TO loom_app: only called from within
-- the security-definer functions below.

-- roles_set_tier (R2 follow-up): same T1-3 promotion rules as 0001, but now
-- resolves an existing target's account through staff.account_id rather
-- than always re-deriving it from accounts.username.
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
        RAISE EXCEPTION 'roles_set_tier may only set tiers 1-3 in Phase 1; T4/T5 grants go through roles_propose_tier/roles_approve_proposal';
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
        IF NOT ((old_tier = 1 AND p_new_tier = 2) OR (old_tier = 2 AND p_new_tier = 1)) THEN
            RAISE EXCEPTION 'domain leads (T3) may only promote T1 to T2 or demote T2 to T1';
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

    target_account := public.roles_resolve_account(p_target_uid);

    INSERT INTO public.staff (uid, account_id, tier)
    VALUES (p_target_uid, target_account, p_new_tier)
    ON CONFLICT (uid) DO UPDATE SET tier = EXCLUDED.tier;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_target_uid, old_tier, p_new_tier, NULL, p_actor, p_reason);
END;
$$;

-- ---------------------------------------------------------------------------
-- §6 (D-S2.6): two-root rule for T4/T5 tier changes.
-- ---------------------------------------------------------------------------

CREATE TABLE role_proposals (
    id           BIGSERIAL PRIMARY KEY,
    target_uid   TEXT NOT NULL,
    new_tier     SMALLINT NOT NULL CHECK (new_tier BETWEEN 1 AND 5),
    proposer     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    approved_by  TEXT,
    applied_at   TIMESTAMPTZ
);

-- roles_propose_tier: a T5 (root) proposes a T4/T5 grant, or the demotion
-- of an existing T4/T5 account. Never applies anything itself -- it only
-- records the proposal for a *second* root to approve.
CREATE OR REPLACE FUNCTION public.roles_propose_tier(
    p_actor     TEXT,
    p_target    TEXT,
    p_new_tier  SMALLINT,
    p_reason    TEXT
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier  SMALLINT;
    target_tier SMALLINT;
    proposal_id BIGINT;
BEGIN
    IF p_actor IS NULL OR p_target IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, target uid and reason are required';
    END IF;

    IF p_actor = p_target THEN
        RAISE EXCEPTION 'a root may not propose a tier change for itself';
    END IF;

    IF p_new_tier IS NULL OR p_new_tier < 1 OR p_new_tier > 5 THEN
        RAISE EXCEPTION 'invalid tier %', p_new_tier;
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 5 THEN
        RAISE EXCEPTION 'only a T5 root may propose a T4/T5 tier change';
    END IF;

    SELECT tier INTO target_tier FROM public.staff WHERE uid = p_target;
    target_tier := COALESCE(target_tier, 0);

    IF NOT (p_new_tier IN (4, 5) OR target_tier IN (4, 5)) THEN
        RAISE EXCEPTION 'roles_propose_tier is only for granting T4/T5 or demoting an existing T4/T5 account';
    END IF;

    INSERT INTO public.role_proposals (target_uid, new_tier, proposer, reason)
    VALUES (p_target, p_new_tier, p_actor, p_reason)
    RETURNING id INTO proposal_id;

    RETURN proposal_id;
END;
$$;

REVOKE ALL ON FUNCTION public.roles_propose_tier(TEXT, TEXT, SMALLINT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.roles_propose_tier(TEXT, TEXT, SMALLINT, TEXT) TO loom_app;

-- roles_approve_proposal: a *second* T5 root applies a pending proposal.
-- The approver must differ from both the proposer and the target, and the
-- proposal must be unexpired and not already applied. Writes role_changes
-- naming both roots and the proposal id.
CREATE OR REPLACE FUNCTION public.roles_approve_proposal(
    p_actor TEXT,
    p_id    BIGINT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier   SMALLINT;
    proposal     public.role_proposals%ROWTYPE;
    old_tier     SMALLINT;
    target_account UUID;
BEGIN
    IF p_actor IS NULL OR p_id IS NULL THEN
        RAISE EXCEPTION 'actor and proposal id are required';
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 5 THEN
        RAISE EXCEPTION 'only a T5 root may approve a two-root proposal';
    END IF;

    SELECT * INTO proposal FROM public.role_proposals WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such proposal %', p_id;
    END IF;

    IF proposal.applied_at IS NOT NULL THEN
        RAISE EXCEPTION 'proposal % has already been applied', p_id;
    END IF;

    IF proposal.expires_at <= NOW() THEN
        RAISE EXCEPTION 'proposal % has expired', p_id;
    END IF;

    IF p_actor = proposal.proposer THEN
        RAISE EXCEPTION 'the proposer may not approve its own proposal';
    END IF;

    IF p_actor = proposal.target_uid THEN
        RAISE EXCEPTION 'the target of a proposal may not approve it';
    END IF;

    SELECT tier INTO old_tier FROM public.staff WHERE uid = proposal.target_uid;
    old_tier := COALESCE(old_tier, 0);

    target_account := public.roles_resolve_account(proposal.target_uid);

    INSERT INTO public.staff (uid, account_id, tier)
    VALUES (proposal.target_uid, target_account, proposal.new_tier)
    ON CONFLICT (uid) DO UPDATE SET tier = EXCLUDED.tier;

    UPDATE public.role_proposals
    SET approved_by = p_actor, applied_at = NOW()
    WHERE id = p_id;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (
        proposal.target_uid,
        old_tier,
        proposal.new_tier,
        NULL,
        p_actor,
        format(
            'two-root proposal #%s: proposed by %s, approved by %s -- %s',
            p_id, proposal.proposer, p_actor, proposal.reason
        )
    );
END;
$$;

REVOKE ALL ON FUNCTION public.roles_approve_proposal(TEXT, BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.roles_approve_proposal(TEXT, BIGINT) TO loom_app;

-- role_proposals is never touched directly by loom_app; only through the
-- two functions above.

-- ---------------------------------------------------------------------------
-- §5 (D-S2.5): NOTIFY roles_changed on every write to a roles table, so the
-- driver's snapshot loader can refresh promptly (in addition to the
-- immediate refresh after its own mutation efun and the expiry timer).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.notify_roles_changed() RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    PERFORM pg_notify('roles_changed', TG_TABLE_NAME);
    RETURN NULL;
END;
$$;

CREATE TRIGGER staff_notify_roles_changed
AFTER INSERT OR UPDATE OR DELETE ON public.staff
FOR EACH STATEMENT EXECUTE FUNCTION public.notify_roles_changed();

CREATE TRIGGER domains_notify_roles_changed
AFTER INSERT OR UPDATE OR DELETE ON public.domains
FOR EACH STATEMENT EXECUTE FUNCTION public.notify_roles_changed();

CREATE TRIGGER domain_members_notify_roles_changed
AFTER INSERT OR UPDATE OR DELETE ON public.domain_members
FOR EACH STATEMENT EXECUTE FUNCTION public.notify_roles_changed();

CREATE TRIGGER tier_policy_notify_roles_changed
AFTER INSERT OR UPDATE OR DELETE ON public.tier_policy
FOR EACH STATEMENT EXECUTE FUNCTION public.notify_roles_changed();

CREATE TRIGGER grants_notify_roles_changed
AFTER INSERT OR UPDATE OR DELETE ON public.grants
FOR EACH STATEMENT EXECUTE FUNCTION public.notify_roles_changed();

-- ---------------------------------------------------------------------------
-- §5 (D-S2.5): audit_log -- the Postgres sink for the driver's in-memory
-- decision ring. loom_app may only INSERT (append-only); it can never
-- read, update or delete an entry once written.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kind                TEXT NOT NULL,
    caller              TEXT,
    effective_principal TEXT,
    apply               TEXT,
    class               SMALLINT,
    argument            TEXT,
    guard_set           TEXT[],
    verdict             TEXT NOT NULL CHECK (verdict IN ('allow', 'deny')),
    detail              TEXT
);

GRANT INSERT ON public.audit_log TO loom_app;
GRANT USAGE ON SEQUENCE public.audit_log_id_seq TO loom_app;

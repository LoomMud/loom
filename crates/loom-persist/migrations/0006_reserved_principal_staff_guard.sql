-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-276 (CTO review of LoomMud/loom#102, B1/OBI-237): a staff JWT `sub`
-- is used directly as the world-side euid for admin queries, and will be
-- for file ops too (M-FS-1). `root`, `mudlib`, and anything with a `:` in
-- it (`domain:<d>`) are the driver's own trusted principal names
-- (`loom_vm::security::is_reserved_principal`): `root` interns to `ROOT`
-- (sym 0), and a guard set holding it is the *empty* guard set, i.e. full
-- privilege. No account may ever be staffed under one of these uids.
--
-- `loom-persist`'s Rust layer already refuses this before issuing any of
-- these statements (see `is_reserved_principal` in `src/lib.rs`); this
-- migration adds the same check inside the security-definer functions
-- themselves, so a future caller that reaches these functions some other
-- way than today's Rust wrappers still cannot create or promote a staff
-- row to a reserved uid.
CREATE OR REPLACE FUNCTION public.is_reserved_principal(p_uid TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT p_uid = 'root' OR p_uid = 'mudlib' OR p_uid LIKE '%:%';
$$;

REVOKE ALL ON FUNCTION public.is_reserved_principal(TEXT) FROM PUBLIC;
-- Intentionally no GRANT EXECUTE ... TO loom_app: only called from within
-- the security-definer functions below, same pattern as
-- `roles_resolve_account` in 0002_roles_s2.sql.

-- roles_bootstrap_root (0001_init.sql): the *only* way to create a T5 row
-- in Phase 1 (owner-only, not reachable via loom_app). Per CTO review of
-- this PR: an operator bootstrapping the first root is exactly the kind
-- of caller most likely to pick the uid `root`, and without this check
-- they would get a T5 staff row that silently can never log in (refused
-- by the login/token-issue guards in `src/lib.rs`) -- a confusing failure
-- mode in place of a clear one at bootstrap time.
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

    IF public.is_reserved_principal(p_uid) THEN
        RAISE EXCEPTION 'uid % is a reserved driver principal and cannot be staff', p_uid;
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
-- Intentionally no GRANT EXECUTE ... TO loom_app here (unchanged from
-- 0001_init.sql).

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

    IF public.is_reserved_principal(p_target_uid) THEN
        RAISE EXCEPTION 'uid % is a reserved driver principal and cannot be staff', p_target_uid;
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

    IF public.is_reserved_principal(p_target) THEN
        RAISE EXCEPTION 'uid % is a reserved driver principal and cannot be staff', p_target;
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

-- roles_approve_proposal is the second and last place a staff row's uid
-- can be set (the target was already checked in roles_propose_tier above,
-- but this re-checks it at apply time too -- a proposal created before
-- this migration ran could still name a reserved uid).
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

    IF public.is_reserved_principal(proposal.target_uid) THEN
        RAISE EXCEPTION 'uid % is a reserved driver principal and cannot be staff', proposal.target_uid;
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

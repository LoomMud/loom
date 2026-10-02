-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-174 (D-P2.5): staff web auth -- TOTP enrolment, refresh-token session
-- bookkeeping, and GitHub identity linking for the optional OIDC login.
-- Runs as `loom_owner`, same as 0001/0002.
--
-- Tier itself never moves here -- this migration only adds the columns and
-- tables `loom-http`'s auth layer needs to issue/refresh sessions and to
-- require/verify a second factor. Every token issue and refresh still reads
-- `staff.tier` directly (see loom-http::auth), never a cached or claimed
-- value.

-- ---------------------------------------------------------------------------
-- TOTP (design §9, D-P2.5): a staff row gets at most one enrolled secret.
-- `totp_confirmed_at` is NULL until the staff member proves control of the
-- secret by submitting one valid code (see `auth_totp_confirm`); until then
-- `totp_secret` is "pending" and does not satisfy the T3+ mandatory-TOTP
-- gate in loom-http. Re-enrolling (`auth_totp_enroll`) always clears
-- `totp_confirmed_at`, so swapping the secret never silently keeps an old
-- confirmation valid for a secret nobody has proven.
-- ---------------------------------------------------------------------------

ALTER TABLE staff ADD COLUMN totp_secret TEXT;
ALTER TABLE staff ADD COLUMN totp_confirmed_at TIMESTAMPTZ;

-- auth_totp_enroll: self-service only (D-27.2 pattern: re-check in SQL, not
-- just at the app layer). p_actor must equal p_uid -- nobody, not even an
-- arch, resets another uid's TOTP secret through this function. (An
-- admin-driven reset flow for a lost device is deliberately deferred; see
-- the OBI-174 PR description.)
CREATE OR REPLACE FUNCTION public.auth_totp_enroll(
    p_actor  TEXT,
    p_uid    TEXT,
    p_secret TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_secret IS NULL THEN
        RAISE EXCEPTION 'actor, uid and secret are required';
    END IF;

    IF p_actor <> p_uid THEN
        RAISE EXCEPTION 'TOTP enrolment is self-service only';
    END IF;

    UPDATE public.staff
    SET totp_secret = p_secret, totp_confirmed_at = NULL
    WHERE uid = p_uid;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no staff row for %', p_uid;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_totp_enroll(TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_totp_enroll(TEXT, TEXT, TEXT) TO loom_app;

-- auth_totp_confirm: marks the already-enrolled secret confirmed. Callers
-- (loom-http) only invoke this after verifying a code against the pending
-- secret, so this function itself does not re-verify a code -- it just
-- records that loom-http already did, same division of labour as the rest
-- of the auth layer (Argon2 verification happens in loom-persist/loom-http,
-- not in SQL).
CREATE OR REPLACE FUNCTION public.auth_totp_confirm(
    p_actor TEXT,
    p_uid   TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL THEN
        RAISE EXCEPTION 'actor and uid are required';
    END IF;

    IF p_actor <> p_uid THEN
        RAISE EXCEPTION 'TOTP confirmation is self-service only';
    END IF;

    UPDATE public.staff
    SET totp_confirmed_at = NOW()
    WHERE uid = p_uid AND totp_secret IS NOT NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no pending TOTP enrolment for %', p_uid;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_totp_confirm(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_totp_confirm(TEXT, TEXT) TO loom_app;

-- ---------------------------------------------------------------------------
-- Refresh-token session bookkeeping (design §9, D-P2.5). This is session
-- state, not a roles table -- `loom_app` gets direct SELECT/INSERT/UPDATE,
-- the same treatment as `accounts`/`object_state` in 0001_init.sql, not the
-- security-definer-only treatment `staff`/`domains`/`grants` get. Only the
-- *hash* of a refresh token is ever stored (`loom-http` hashes with
-- SHA-256 before every query), so a leaked row never yields a usable token.
-- ---------------------------------------------------------------------------

CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staff_uid   TEXT NOT NULL REFERENCES staff(uid),
    token_hash  TEXT NOT NULL UNIQUE,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX refresh_tokens_staff_uid_idx ON refresh_tokens (staff_uid);

GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO loom_app;

-- ---------------------------------------------------------------------------
-- GitHub identity linking (design §9, D-P2.5): "optional GitHub OIDC login,
-- linked to an existing staff row (never creates staff)". Linking itself is
-- a privileged, auditable action -- only T4+ (arch/root) may create a link,
-- same actor-tier floor as `roles_grant`/`roles_revoke_grant` -- so a
-- compromised GitHub account can never *become* staff, only ever log in as
-- a uid an arch has already vouched for out of band.
-- ---------------------------------------------------------------------------

CREATE TABLE github_identities (
    github_id  BIGINT PRIMARY KEY,
    staff_uid  TEXT NOT NULL UNIQUE REFERENCES staff(uid),
    linked_by  TEXT NOT NULL,
    linked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

GRANT SELECT ON github_identities TO loom_app;

CREATE OR REPLACE FUNCTION public.auth_github_link(
    p_actor     TEXT,
    p_uid       TEXT,
    p_github_id BIGINT,
    p_reason    TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier SMALLINT;
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_github_id IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, uid, github id and reason are required';
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 4 THEN
        RAISE EXCEPTION 'actor tier % may not link a GitHub identity', actor_tier;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.staff WHERE uid = p_uid) THEN
        RAISE EXCEPTION 'no staff row for % -- GitHub login never creates staff', p_uid;
    END IF;

    INSERT INTO public.github_identities (github_id, staff_uid, linked_by)
    VALUES (p_github_id, p_uid, p_actor);

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_uid, NULL, NULL, NULL, p_actor, format('linked GitHub id %s -- %s', p_github_id, p_reason));
END;
$$;

REVOKE ALL ON FUNCTION public.auth_github_link(TEXT, TEXT, BIGINT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_github_link(TEXT, TEXT, BIGINT, TEXT) TO loom_app;

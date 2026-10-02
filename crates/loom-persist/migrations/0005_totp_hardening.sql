-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-199 (follow-up to Aragorn's review of PR #73 / OBI-195, design
-- threat-model-phase2.md §6.1 M-AUTH-3/M-AUTH-8/M-ADM-2): TOTP secrets
-- encrypted at rest, single-use hashed recovery codes, a `mfa_at`
-- freshness column for step-up auth, and step-up gating on
-- `auth_github_link`/`auth_github_unlink` (M-AUTH-7).
--
-- Runs as `loom_owner`, same as 0001-0003.

-- ---------------------------------------------------------------------------
-- TOTP secret encryption (M-AUTH-8). `staff.totp_secret` was plaintext
-- TEXT in 0003. Postgres never sees the plaintext again: `loom-http`
-- encrypts with XChaCha20-Poly1305 (AAD-bound to the uid) under a key read
-- once at boot from the secret file, and only ever writes/reads the
-- resulting ciphertext blob (24-byte nonce || ciphertext || 16-byte tag).
--
-- There is no in-SQL re-encryption step: this migration predates any real
-- deployment (`LOOM_JWT_SECRET`/`LOOM_TOTP_ENC_KEY` have never been set in
-- any environment -- see the OBI-199 deploy gate), so there are no
-- existing plaintext secrets to carry forward. A later migration touching
-- a table that *does* hold production data must instead add the new
-- column, backfill it from the app (which holds the key Postgres never
-- gets), and only then drop the old column in a follow-up migration --
-- noted here so this isn't read as "it's fine to just drop a column with
-- live data in it".
-- ---------------------------------------------------------------------------

ALTER TABLE staff ADD COLUMN totp_secret_enc BYTEA;
ALTER TABLE staff DROP COLUMN totp_secret;

-- `mfa_at`: the last time this uid's session proved possession of its
-- second factor (a TOTP code or a recovery code), updated by
-- `auth_mfa_touch`. Step-up-gated actions below require this to be no
-- more than 5 minutes old; `loom-http` also enforces the same 5-minute
-- window at the app layer (defense in depth, and the only layer that can
-- give a client a useful "please re-enter your code" error instead of a
-- bare SQL exception).
ALTER TABLE staff ADD COLUMN mfa_at TIMESTAMPTZ;

-- auth_mfa_touch: self-service only, same actor-equals-uid pattern as
-- auth_totp_enroll/confirm. Called by loom-http right after a login or a
-- dedicated step-up re-verification accepts a TOTP/recovery code.
CREATE OR REPLACE FUNCTION public.auth_mfa_touch(
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
        RAISE EXCEPTION 'mfa_at may only be touched by the uid itself';
    END IF;

    UPDATE public.staff SET mfa_at = NOW() WHERE uid = p_uid;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no staff row for %', p_uid;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_mfa_touch(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_mfa_touch(TEXT, TEXT) TO loom_app;

-- auth_totp_enroll: same self-service shape as 0003, now takes the
-- ciphertext blob instead of a plaintext base32 secret, and also clears
-- any outstanding recovery codes -- re-enrolling invalidates the old
-- secret's recovery codes along with the secret itself, since they were
-- only ever a backup for *that* secret's loss.
CREATE OR REPLACE FUNCTION public.auth_totp_enroll(
    p_actor  TEXT,
    p_uid    TEXT,
    p_secret BYTEA
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
    SET totp_secret_enc = p_secret, totp_confirmed_at = NULL
    WHERE uid = p_uid;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no staff row for %', p_uid;
    END IF;

    DELETE FROM public.totp_recovery_codes WHERE uid = p_uid;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_totp_enroll(TEXT, TEXT, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_totp_enroll(TEXT, TEXT, BYTEA) TO loom_app;

-- auth_totp_confirm (0003) referenced the now-dropped `totp_secret`
-- column; re-declared here against `totp_secret_enc`. Behaviour is
-- otherwise unchanged: it only records that loom-http already verified a
-- code, it does not re-verify one itself.
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
    WHERE uid = p_uid AND totp_secret_enc IS NOT NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no pending TOTP enrolment for %', p_uid;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_totp_confirm(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_totp_confirm(TEXT, TEXT) TO loom_app;

-- auth_totp_admin_reset: an admin (T4+) clearing a *different* uid's TOTP
-- enrolment (lost device recovery), distinct from self re-enrolment above.
-- Requires the actor's own step-up (`mfa_at` fresh within 5 minutes) same
-- as auth_github_link/auth_github_unlink below. Leaves the target with
-- no secret at all, so its next login goes through the T3+ bootstrap
-- enrolment-only credential path, exactly like a brand new T3+ account.
CREATE OR REPLACE FUNCTION public.auth_totp_admin_reset(
    p_actor  TEXT,
    p_uid    TEXT,
    p_reason TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier SMALLINT;
    actor_mfa_at TIMESTAMPTZ;
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, uid and reason are required';
    END IF;

    SELECT tier, mfa_at INTO actor_tier, actor_mfa_at FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 4 THEN
        RAISE EXCEPTION 'actor tier % may not reset another uid''s TOTP enrolment', actor_tier;
    END IF;

    IF actor_mfa_at IS NULL OR actor_mfa_at <= NOW() - INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'step-up required: actor''s mfa_at is not fresh';
    END IF;

    UPDATE public.staff
    SET totp_secret_enc = NULL, totp_confirmed_at = NULL
    WHERE uid = p_uid;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no staff row for %', p_uid;
    END IF;

    DELETE FROM public.totp_recovery_codes WHERE uid = p_uid;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_uid, NULL, NULL, NULL, p_actor, format('admin TOTP reset -- %s', p_reason));
END;
$$;

REVOKE ALL ON FUNCTION public.auth_totp_admin_reset(TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_totp_admin_reset(TEXT, TEXT, TEXT) TO loom_app;

-- ---------------------------------------------------------------------------
-- Recovery codes (M-AUTH-8): 10 single-use codes issued whenever a TOTP
-- secret is confirmed. Only the SHA-256 hash is ever stored, same
-- treatment as refresh_tokens -- a leaked row never yields a usable code.
-- ---------------------------------------------------------------------------

CREATE TABLE totp_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    uid        TEXT NOT NULL REFERENCES staff(uid),
    code_hash  TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at    TIMESTAMPTZ
);

CREATE INDEX totp_recovery_codes_uid_idx ON totp_recovery_codes (uid);

GRANT SELECT, INSERT, UPDATE, DELETE ON totp_recovery_codes TO loom_app;

-- auth_recovery_codes_store: self-service only, replaces the full set of
-- 10 codes atomically (delete-then-insert in one statement each, same
-- transaction).
CREATE OR REPLACE FUNCTION public.auth_recovery_codes_store(
    p_actor      TEXT,
    p_uid        TEXT,
    p_code_hashes TEXT[]
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_code_hashes IS NULL THEN
        RAISE EXCEPTION 'actor, uid and code hashes are required';
    END IF;

    IF p_actor <> p_uid THEN
        RAISE EXCEPTION 'recovery codes may only be (re)issued by the uid itself';
    END IF;

    DELETE FROM public.totp_recovery_codes WHERE uid = p_uid;

    INSERT INTO public.totp_recovery_codes (uid, code_hash)
    SELECT p_uid, h FROM unnest(p_code_hashes) AS h;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_recovery_codes_store(TEXT, TEXT, TEXT[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_recovery_codes_store(TEXT, TEXT, TEXT[]) TO loom_app;

-- auth_recovery_code_consume: atomically claims a single-use code by its
-- hash (`UPDATE ... WHERE used_at IS NULL`, so two concurrent attempts
-- with the same stolen code can't both succeed). No actor check -- the
-- code's own 128+ bits of entropy *is* the credential, the same trust
-- model as a refresh token hash lookup.
CREATE OR REPLACE FUNCTION public.auth_recovery_code_consume(
    p_uid       TEXT,
    p_code_hash TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    claimed INT;
BEGIN
    IF p_uid IS NULL OR p_code_hash IS NULL THEN
        RETURN FALSE;
    END IF;

    UPDATE public.totp_recovery_codes
    SET used_at = NOW()
    WHERE uid = p_uid AND code_hash = p_code_hash AND used_at IS NULL;

    GET DIAGNOSTICS claimed = ROW_COUNT;
    RETURN claimed > 0;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_recovery_code_consume(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_recovery_code_consume(TEXT, TEXT) TO loom_app;

-- ---------------------------------------------------------------------------
-- GitHub link/unlink step-up (M-AUTH-7, M-ADM-2): `auth_github_link`
-- (0003) and `auth_github_unlink` (0004, OBI-200) now also require the
-- actor's own step-up (`mfa_at` fresh within 5 minutes), on top of the
-- existing T4+ floor. No renaming -- loom-persist already calls these by
-- these names.
-- ---------------------------------------------------------------------------

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
    actor_mfa_at TIMESTAMPTZ;
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_github_id IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, uid, github id and reason are required';
    END IF;

    SELECT tier, mfa_at INTO actor_tier, actor_mfa_at FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 4 THEN
        RAISE EXCEPTION 'actor tier % may not link a GitHub identity', actor_tier;
    END IF;

    IF actor_mfa_at IS NULL OR actor_mfa_at <= NOW() - INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'step-up required: actor''s mfa_at is not fresh';
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

CREATE OR REPLACE FUNCTION public.auth_github_unlink(
    p_actor  TEXT,
    p_uid    TEXT,
    p_reason TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actor_tier SMALLINT;
    actor_mfa_at TIMESTAMPTZ;
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, uid and reason are required';
    END IF;

    SELECT tier, mfa_at INTO actor_tier, actor_mfa_at FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 4 THEN
        RAISE EXCEPTION 'actor tier % may not unlink a GitHub identity', actor_tier;
    END IF;

    IF actor_mfa_at IS NULL OR actor_mfa_at <= NOW() - INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'step-up required: actor''s mfa_at is not fresh';
    END IF;

    DELETE FROM public.github_identities WHERE staff_uid = p_uid;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no linked GitHub identity for %', p_uid;
    END IF;

    INSERT INTO public.role_changes (uid, old_tier, new_tier, domain, actor, reason)
    VALUES (p_uid, NULL, NULL, NULL, p_actor, format('unlinked GitHub identity -- %s', p_reason));
END;
$$;

REVOKE ALL ON FUNCTION public.auth_github_unlink(TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_github_unlink(TEXT, TEXT, TEXT) TO loom_app;

-- ---------------------------------------------------------------------------
-- Role-change step-up (M-ADM-2) -- deliberately NOT done here.
--
-- `roles_set_tier`/`roles_approve_proposal` (0002) are reached today only
-- from the in-world `/secure/roles` efuns (loom-vm), driven over telnet --
-- a path that has no concept of `mfa_at` at all (it isn't a web/JWT
-- session, and most staff who promote/demote in-game have never touched
-- `/auth/*`). Gating these functions on a fresh `mfa_at` here would not
-- add step-up to that path, it would simply break it permanently: every
-- in-game role change would start failing with "step-up required" and
-- there would be no way to clear it short of logging into the (not yet
-- built) admin UI.
--
-- The right place for this check is the future HTTP-driven role-change
-- endpoint (part of the admin UI, M-ADM-2's actual subject -- "the UI
-- re-prompts for TOTP"), which can enforce it the same way
-- `auth_github_link`/`auth_github_unlink` do above, at the point it calls
-- `Persist::roles_set_tier`/`roles_approve_proposal`. Tracked as a
-- follow-up alongside the admin UI itself rather than implemented
-- speculatively against a caller that doesn't exist yet.
-- ---------------------------------------------------------------------------

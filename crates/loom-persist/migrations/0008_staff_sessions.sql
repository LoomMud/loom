-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-198 (D-TM2, M-AUTH-5, M-AUTH-6), rebased onto OBI-197/OBI-203: turns
-- `refresh_tokens` into `staff_sessions` in place (same table, renamed --
-- grants on it already carry over, no re-GRANT needed), adds the 24h idle
-- window (`last_used_at`), and adds the M-AUTH-5 revoke-all-for-uid
-- triggers on `staff` (tier or TOTP-secret change, row delete), `accounts`
-- (password_hash change), and `github_identities` (unlink).
--
-- `sid` (added by 0005_refresh_token_session.sql) is reused as the
-- family id M-AUTH-5 talks about -- one family id, not two: rotation
-- (loom-http's `AuthService::refresh`, backed by `Persist::session_rotate`)
-- already carries `sid` forward unchanged across every row in a family,
-- same as it carries `amr`/`mfa_at` forward, so reuse detection and
-- logout both key off `sid`.
--
-- Runs as `loom_owner`, same as 0001-0005.

ALTER TABLE refresh_tokens RENAME TO staff_sessions;
ALTER INDEX refresh_tokens_pkey RENAME TO staff_sessions_pkey;
ALTER INDEX refresh_tokens_token_hash_key RENAME TO staff_sessions_token_hash_key;
ALTER INDEX refresh_tokens_staff_uid_idx RENAME TO staff_sessions_staff_uid_idx;
ALTER INDEX refresh_tokens_sid_idx RENAME TO staff_sessions_sid_idx;

-- M-AUTH-5: "expires_at (14 days absolute, 24h idle)". `last_used_at` is
-- updated to `NOW()` on every successful rotation (`session_rotate`'s
-- `INSERT`, see below) -- idle time is "time since this family was last
-- used to refresh", not "time since the family's login".
ALTER TABLE staff_sessions ADD COLUMN last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- `ON DELETE CASCADE` so staff-row removal (M-AUTH-5: "removal of the
-- staff row" revokes sessions) can actually happen: the original FK (from
-- 0003, still named `refresh_tokens_staff_uid_fkey` -- renaming a table
-- doesn't rename its constraints) was `ON DELETE NO ACTION`, which would
-- make `DELETE FROM staff` fail outright with any session outstanding,
-- before the revoke-on-delete trigger below ever got a chance to run.
ALTER TABLE staff_sessions DROP CONSTRAINT refresh_tokens_staff_uid_fkey;
ALTER TABLE staff_sessions
    ADD CONSTRAINT staff_sessions_staff_uid_fkey
    FOREIGN KEY (staff_uid) REFERENCES staff(uid) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- M-AUTH-5: "Revoke all families for a uid on password change, TOTP
-- reset, GitHub unlink, a tier change, or removal of the staff row.
-- Implement this as a trigger ... so no code path can forget it."
--
-- Must-fix 2 (OBI-198 re-review): a concurrent `session_rotate` and a
-- revoke-all for the same uid must not race each other into leaving an
-- unrevoked row behind. `staff_sessions_revoke_for_uid` takes
-- `FOR UPDATE` on the `staff` row before its `UPDATE`; `session_rotate`
-- takes `FOR SHARE` on the same row before its guarded consume+insert
-- (see loom-persist's `Persist::session_rotate`). `FOR UPDATE` conflicts
-- with `FOR SHARE`, so whichever side asks for the lock first completes
-- first, and the other sees a fully-committed, consistent result: if the
-- revoke goes first, the rotation's guarded `UPDATE` in `session_rotate`
-- finds the row already `revoked_at`-stamped and refuses; if the
-- rotation goes first, the revoke's `UPDATE`, as a later statement under
-- READ COMMITTED, gets a fresh snapshot that includes the newly-inserted
-- row. (The trigger on `staff` itself already holds the row's lock as
-- part of the triggering `UPDATE`/`DELETE`, so the explicit `FOR UPDATE`
-- in `staff_sessions_revoke_for_uid` only does new work for the
-- `accounts`/`github_identities` triggers below, but taking it
-- unconditionally keeps one code path instead of two.)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.staff_sessions_revoke_for_uid(p_uid TEXT) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    PERFORM 1 FROM public.staff WHERE uid = p_uid FOR UPDATE;
    UPDATE public.staff_sessions
    SET revoked_at = NOW()
    WHERE staff_uid = p_uid AND revoked_at IS NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.staff_sessions_revoke_for_uid(TEXT) FROM PUBLIC;
-- No GRANT EXECUTE to loom_app: only reachable from the triggers below
-- (and, later, from inside other security-definer functions), never
-- called directly by the app.

-- `session_rotate` (loom-persist) needs `SELECT ... FOR SHARE` on the
-- owning `staff` row to serialize against the revoke functions above --
-- but Postgres's row-locking clauses require `UPDATE`/`DELETE` privilege
-- on the table, not just `SELECT` (`loom_app` only ever gets `SELECT` on
-- `staff`, D-27.4), so that lock has to be taken through a
-- `security definer` wrapper too.
CREATE OR REPLACE FUNCTION public.staff_sessions_lock_for_rotate(p_uid TEXT) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    PERFORM 1 FROM public.staff WHERE uid = p_uid FOR SHARE;
END;
$$;

REVOKE ALL ON FUNCTION public.staff_sessions_lock_for_rotate(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.staff_sessions_lock_for_rotate(TEXT) TO loom_app;

-- OBI-219 (re-review of OBI-198/PR #77, same shape as must-fix 2):
-- logout (`Persist::session_revoke_family_by_token`) revokes a whole
-- family by `sid`, keyed off the presented token's row, but that row's
-- `UPDATE` previously took no lock on the owning `staff` row at all. A
-- `session_rotate` in flight on the same family only takes `FOR SHARE`
-- on `staff` (see above), which does not conflict with an unlocked
-- `UPDATE staff_sessions`, so the old session's `UPDATE ... WHERE sid =
-- (...)` could run, find, and revoke the old (pre-rotation) row while
-- the rotation is still uncommitted, and then under READ COMMITTED's
-- EvalPlanQual the logout's `UPDATE` never re-checks the newly
-- inserted row once the rotation commits -- the rotated session
-- survives logout. Taking `FOR UPDATE` on `staff` first, same as
-- `staff_sessions_revoke_for_uid`, forces this to serialize against
-- `session_rotate`'s `FOR SHARE` exactly like every other revoke path.
CREATE OR REPLACE FUNCTION public.staff_sessions_revoke_family(p_token_hash TEXT) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_uid TEXT;
    v_sid TEXT;
BEGIN
    SELECT staff_uid, sid INTO v_uid, v_sid
    FROM public.staff_sessions WHERE token_hash = p_token_hash;

    IF NOT FOUND THEN
        -- Unknown token: a no-op, same as the previous plain UPDATE.
        RETURN;
    END IF;

    PERFORM 1 FROM public.staff WHERE uid = v_uid FOR UPDATE;

    UPDATE public.staff_sessions
    SET revoked_at = NOW()
    WHERE sid = v_sid AND revoked_at IS NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.staff_sessions_revoke_family(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.staff_sessions_revoke_family(TEXT) TO loom_app;

-- Tier change, TOTP (re-)enrolment, or staff-row removal.
CREATE OR REPLACE FUNCTION public.staff_sessions_revoke_on_staff_change() RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM public.staff_sessions_revoke_for_uid(OLD.uid);
        RETURN OLD;
    END IF;

    IF OLD.tier IS DISTINCT FROM NEW.tier OR OLD.totp_secret IS DISTINCT FROM NEW.totp_secret THEN
        PERFORM public.staff_sessions_revoke_for_uid(NEW.uid);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER staff_sessions_revoke_on_staff_change
AFTER UPDATE OR DELETE ON public.staff
FOR EACH ROW EXECUTE FUNCTION public.staff_sessions_revoke_on_staff_change();

-- Password change (accounts.password_hash). Fires for *every* account,
-- not just staff -- a harmless no-op for a player account, which has no
-- staff row and therefore no sessions to revoke.
CREATE OR REPLACE FUNCTION public.staff_sessions_revoke_on_password_change() RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    staff_row public.staff%ROWTYPE;
BEGIN
    IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN
        SELECT * INTO staff_row FROM public.staff WHERE account_id = NEW.id;
        IF FOUND THEN
            PERFORM public.staff_sessions_revoke_for_uid(staff_row.uid);
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER staff_sessions_revoke_on_password_change
AFTER UPDATE ON public.accounts
FOR EACH ROW EXECUTE FUNCTION public.staff_sessions_revoke_on_password_change();

-- GitHub unlink (auth_github_unlink, 0004_github_unlink.sql, does
-- `DELETE FROM github_identities WHERE staff_uid = p_uid`).
CREATE OR REPLACE FUNCTION public.staff_sessions_revoke_on_github_unlink() RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    PERFORM public.staff_sessions_revoke_for_uid(OLD.staff_uid);
    RETURN OLD;
END;
$$;

CREATE TRIGGER staff_sessions_revoke_on_github_unlink
AFTER DELETE ON public.github_identities
FOR EACH ROW EXECUTE FUNCTION public.staff_sessions_revoke_on_github_unlink();

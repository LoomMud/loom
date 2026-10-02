-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-200 follow-up to OBI-174/OBI-195: `auth_github_unlink`, the missing
-- counterpart to `auth_github_link` (0003_staff_auth.sql). Same actor-tier
-- floor (T4+) and the same "self-service only" shape does not apply here --
-- unlinking, like linking, is an arch/root action taken on someone else's
-- behalf (e.g. a lost/compromised GitHub account), not something a staff
-- member does to themselves through this function. Runs as `loom_owner`,
-- same as 0001-0003.

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
BEGIN
    IF p_actor IS NULL OR p_uid IS NULL OR p_reason IS NULL THEN
        RAISE EXCEPTION 'actor, uid and reason are required';
    END IF;

    SELECT tier INTO actor_tier FROM public.staff WHERE uid = p_actor;
    actor_tier := COALESCE(actor_tier, 0);

    IF actor_tier < 4 THEN
        RAISE EXCEPTION 'actor tier % may not unlink a GitHub identity', actor_tier;
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

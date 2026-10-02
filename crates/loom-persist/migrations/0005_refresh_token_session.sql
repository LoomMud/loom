-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-203 (follow-up to OBI-197/PR #76, M-AUTH-4/5 hardening): persist the
-- token-family id and the authentication context a login established, on
-- the `refresh_tokens` row itself, so a rotation can carry them forward
-- instead of inventing a fresh `sid` (breaking M-AUTH-5 reuse detection and
-- family revocation, which are keyed off `sid`) and losing `amr`/`mfa_at`
-- (breaking the M-ADM-2 step-up freshness check across a refresh).
--
-- `sid` is backfilled from `id` for any row that predates this migration
-- (there shouldn't be any in a real deployment yet, but NOT NULL needs a
-- default for the ALTER to succeed either way) -- a stale session created
-- before this migration simply becomes its own one-token family, which is
-- harmless: it just means that *one* pre-existing refresh token doesn't
-- get the benefit of family-wide reuse-detection revocation, same as
-- before this migration existed.

ALTER TABLE refresh_tokens ADD COLUMN sid TEXT;
UPDATE refresh_tokens SET sid = id::text WHERE sid IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN sid SET NOT NULL;

ALTER TABLE refresh_tokens ADD COLUMN amr TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE refresh_tokens ADD COLUMN mfa_at TIMESTAMPTZ;

CREATE INDEX refresh_tokens_sid_idx ON refresh_tokens (sid);

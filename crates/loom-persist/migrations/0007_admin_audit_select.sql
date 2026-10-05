-- SPDX-FileCopyrightText: 2026 Oberfield
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- OBI-185 (P2-O2 admin UI, M-ADM-4): the admin audit view needs
-- `loom_app` to be able to *read* `audit_log`, not just append to it.
-- 0002_roles_s2.sql deliberately granted only `INSERT` (the driver's
-- decision ring is write-only from the app's point of view); the audit
-- view is the first `loom_app` caller that needs to list past entries.
--
-- `loom_app` still gets no `UPDATE`/`DELETE` here -- the sink stays
-- append-only end to end, so the admin audit view (`GET
-- /api/v1/admin/audit`) is mechanically read-only: there is no grant
-- that would let it (or any other `loom_app` code path) mutate a row
-- once written.

GRANT SELECT ON public.audit_log TO loom_app;

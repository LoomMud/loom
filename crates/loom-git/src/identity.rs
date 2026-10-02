// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Commit author identity (D-B3.4): the builder, with a `Signed-off-by`
//! trailer matching, so `warp/scripts/check-dco.sh` passes. Committer is
//! always `loom-driver <driver@loommud.com>`.

/// `name <email>` pair used for both the commit author and its
/// `Signed-off-by` trailer (DCO requires they match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub email: String,
}

impl Identity {
    pub fn new(name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
        }
    }

    /// D-B3.4: GitHub noreply email if the staff row has a linked GitHub
    /// account (O3 OIDC), else `<uid>@users.loommud.com`. Display name is
    /// the uid either way -- a real display name is a `loom-persist`
    /// concern this crate does not have.
    pub fn for_uid(uid: &str, github_noreply_email: Option<&str>) -> Self {
        match github_noreply_email {
            Some(email) => Identity::new(uid, email),
            None => Identity::new(uid, format!("{uid}@users.loommud.com")),
        }
    }

    pub fn author_arg(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }

    pub fn signed_off_by_trailer(&self) -> String {
        format!("Signed-off-by: {} <{}>", self.name, self.email)
    }
}

/// `loom-driver <driver@loommud.com>`: the committer identity for every
/// auto-commit (D-B3.4). Never the author.
pub fn driver_identity() -> Identity {
    Identity::new("loom-driver", "driver@loommud.com")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_github_account_uses_its_noreply_email() {
        let id = Identity::for_uid(
            "glorfindel",
            Some("123+glorfindel@users.noreply.github.com"),
        );
        assert_eq!(id.email, "123+glorfindel@users.noreply.github.com");
        assert_eq!(id.name, "glorfindel");
    }

    #[test]
    fn unlinked_account_falls_back_to_users_loommud_com() {
        let id = Identity::for_uid("appr1", None);
        assert_eq!(id.email, "appr1@users.loommud.com");
    }

    #[test]
    fn trailer_matches_author_for_dco() {
        let id = Identity::for_uid("appr1", None);
        assert_eq!(
            id.signed_off_by_trailer(),
            format!("Signed-off-by: {}", id.author_arg())
        );
    }
}

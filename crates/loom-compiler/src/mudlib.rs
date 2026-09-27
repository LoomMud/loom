// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Whole-mudlib checking (`loom check`, spec §5.10): load sources through a
//! [`SourceLoader`], compile programs in inherit order (parents first, each
//! once), and collect rendered diagnostics per file.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use loom_syntax::{Diagnostic, Span};

use crate::check::{Checked, check_program};
use crate::interface::{ImportInfo, ParentInfo, ProgramInfo};

/// Maximum inherit depth (matches the Phase 0 driver).
pub const MAX_INHERIT_DEPTH: usize = 32;

/// Where program sources come from (the filesystem, or a map in tests).
pub trait SourceLoader {
    /// Source of program `path` (`/std/room` → `<root>/std/room.wf`).
    fn load(&self, path: &str) -> Result<String, String>;
}

/// Loads `<root>/<path>.wf` from disk.
pub struct FsLoader {
    pub root: PathBuf,
}

impl SourceLoader for FsLoader {
    fn load(&self, path: &str) -> Result<String, String> {
        let file = self.root.join(format!("{}.wf", &path[1..]));
        std::fs::read_to_string(&file).map_err(|e| e.to_string())
    }
}

/// In-memory sources keyed by program path (tests, LSP buffers).
impl SourceLoader for HashMap<String, String> {
    fn load(&self, path: &str) -> Result<String, String> {
        self.get(path)
            .cloned()
            .ok_or_else(|| "No such file or directory".to_string())
    }
}

/// Validate and normalise a program path: absolute, no extension, simple
/// segments. Same rules as the Phase 0 driver.
pub fn normalize_path(p: &str) -> Result<String, String> {
    let p = p.trim();
    let p = p.strip_suffix(".wf").unwrap_or(p);
    if !p.starts_with('/') {
        return Err(format!(
            "`{p}`: program paths must be absolute (start with `/`)"
        ));
    }
    for seg in p[1..].split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || !seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "`{p}`: invalid program path (segments may use letters, digits, `_` and `-`)"
            ));
        }
    }
    Ok(p.to_string())
}

/// Outcome of compiling one program.
pub enum Outcome {
    Ok(Checked),
    /// Rendered diagnostics (rustc style, with file:line:col).
    Failed(String),
    /// The file could not be read.
    Missing(String),
}

/// A compile session: caches every program it has compiled.
pub struct Session<L: SourceLoader> {
    loader: L,
    done: BTreeMap<String, Outcome>,
    /// Rendered `09xx` lint warnings (D-P1.4 etc.), by program path. Filled
    /// in for every file that parses cleanly, independent of whether it
    /// goes on to resolve/type-check (these lints are syntax-only).
    warnings: BTreeMap<String, Vec<String>>,
    stack: Vec<String>,
}

impl<L: SourceLoader> Session<L> {
    pub fn new(loader: L) -> Self {
        Session {
            loader,
            done: BTreeMap::new(),
            warnings: BTreeMap::new(),
            stack: Vec::new(),
        }
    }

    /// All outcomes so far, by program path.
    pub fn outcomes(&self) -> &BTreeMap<String, Outcome> {
        &self.done
    }

    /// All rendered lint warnings so far, by program path.
    pub fn warnings(&self) -> &BTreeMap<String, Vec<String>> {
        &self.warnings
    }

    /// Force `path` to be recompiled on the next `.compile(path)` call
    /// (spec §7.2 `compile_object`/`update`): drops its cached [`Outcome`]
    /// so a stale interface can never be reused for it. Callers doing an
    /// incremental recompile must also invalidate every program that
    /// (transitively) inherits/imports `path`, or that program's cached
    /// `Outcome` still refers to `path`'s *old* [`crate::interface::ProgramInfo`]
    /// even though `path` itself now reflects the new one.
    pub fn invalidate(&mut self, path: &str) {
        self.done.remove(path);
        // Lint warnings are recomputed on the next compile; drop stale ones
        // so a fixed file doesn't keep reporting old W09xx warnings.
        self.warnings.remove(path);
    }

    pub fn into_outcomes(self) -> BTreeMap<String, Outcome> {
        self.done
    }

    /// Consume the session, returning outcomes and rendered lint warnings.
    pub fn into_outcomes_and_warnings(
        self,
    ) -> (BTreeMap<String, Outcome>, BTreeMap<String, Vec<String>>) {
        (self.done, self.warnings)
    }

    /// Compile `path` (already normalised) and its ancestors.
    pub fn compile(&mut self, path: &str) -> &Outcome {
        if !self.done.contains_key(path) {
            let o = self.compile_uncached(path);
            self.done.insert(path.to_string(), o);
        }
        &self.done[path]
    }

    fn info(&self, path: &str) -> Option<Rc<ProgramInfo>> {
        match self.done.get(path) {
            Some(Outcome::Ok(c)) => Some(c.info.clone()),
            _ => None,
        }
    }

    fn compile_uncached(&mut self, path: &str) -> Outcome {
        let src = match self.loader.load(path) {
            Ok(s) => s,
            Err(e) => return Outcome::Missing(format!("{path}.wf: cannot read: {e}\n")),
        };
        let (ast, diags) = loom_syntax::parse(&src);
        if !diags.is_empty() {
            return Outcome::Failed(render(path, &src, &diags));
        }
        // Syntax-only lints (D-P1.4 etc., OBI-86) run on every clean parse,
        // even if the program goes on to fail resolve/type-check below.
        let lints = crate::lint::lint_program(&ast, &src);
        if !lints.is_empty() {
            self.warnings.insert(
                path.to_string(),
                lints
                    .iter()
                    .map(|d| d.render(&format!("{path}.wf"), &src))
                    .collect(),
            );
        }
        let mut diags = Vec::new();
        let mut parents = Vec::new();
        for inh in ast.inherits.iter() {
            match self.parent(path, &inh.path, inh.span) {
                Ok(info) => parents.push(ParentInfo {
                    label: inh.label.as_ref().map(|l| Rc::from(l.name.as_str())),
                    info,
                    span: inh.span,
                }),
                Err(d) => diags.push(d),
            }
        }
        let mut imports = Vec::new();
        for imp in ast.imports.iter() {
            match self.import_target(path, &imp.path, imp.span) {
                Ok(info) => imports.push(ImportInfo {
                    info,
                    names: imp
                        .names
                        .as_ref()
                        .map(|ns| ns.iter().map(|n| Rc::from(n.name.as_str())).collect()),
                    span: imp.span,
                }),
                Err(d) => diags.push(d),
            }
        }
        if !diags.is_empty() {
            return Outcome::Failed(render(path, &src, &diags));
        }
        match check_program(path, &ast, parents, imports) {
            Ok(c) => Outcome::Ok(c),
            Err(d) => Outcome::Failed(render(path, &src, &d)),
        }
    }

    fn parent(&mut self, path: &str, raw: &str, span: Span) -> Result<Rc<ProgramInfo>, Diagnostic> {
        self.dependency(path, raw, span, "inherit")
    }

    fn import_target(
        &mut self,
        path: &str,
        raw: &str,
        span: Span,
    ) -> Result<Rc<ProgramInfo>, Diagnostic> {
        self.dependency(path, raw, span, "import")
    }

    /// Resolve and compile `raw` (an `inherit` or `import` target of `path`).
    fn dependency(
        &mut self,
        path: &str,
        raw: &str,
        span: Span,
        what: &str,
    ) -> Result<Rc<ProgramInfo>, Diagnostic> {
        let ppath = normalize_path(raw).map_err(|e| Diagnostic::error("W0110", span, e))?;
        if self.stack.len() >= MAX_INHERIT_DEPTH {
            return Err(
                Diagnostic::error("W0111", span, format!("{what} chain is too deep")).with_hint(
                    format!("at most {MAX_INHERIT_DEPTH} levels of {what} are allowed"),
                ),
            );
        }
        if ppath == path || self.stack.contains(&ppath) {
            return Err(
                Diagnostic::error("W0112", span, format!("{what} cycle through {ppath}"))
                    .with_hint(format!("a program cannot (indirectly) {what} itself")),
            );
        }
        self.stack.push(path.to_string());
        let outcome = self.compile(&ppath);
        let err = match outcome {
            Outcome::Ok(_) => None,
            Outcome::Failed(_) => Some(
                Diagnostic::error(
                    "W0113",
                    span,
                    format!("cannot {what} {ppath}: it has errors"),
                )
                .with_hint(format!("fix the errors reported for {ppath}.wf first")),
            ),
            Outcome::Missing(_) => Some(
                Diagnostic::error(
                    "W0114",
                    span,
                    format!("cannot {what} {ppath}: {ppath}.wf does not exist"),
                )
                .with_hint(format!(
                    "check the path; {what} paths are absolute and have no extension"
                )),
            ),
        };
        self.stack.pop();
        match err {
            Some(d) => Err(d),
            None => Ok(self.info(&ppath).expect("compiled")),
        }
    }
}

fn render(path: &str, src: &str, diags: &[Diagnostic]) -> String {
    let file = format!("{path}.wf");
    diags.iter().map(|d| d.render(&file, src)).collect()
}

/// Result of checking a whole mudlib.
pub struct MudlibReport {
    /// Every program that checked clean, by path.
    pub programs: BTreeMap<String, Checked>,
    /// One rendered report per failing file, sorted by path.
    pub errors: Vec<String>,
    /// Rendered `09xx` lint warnings, sorted by path (D-P1.4 etc., OBI-86).
    /// Warnings never fail `loom check` on their own; see `--deny-warnings`.
    pub warnings: Vec<String>,
}

/// Check every `.wf` file under `root` (`loom check`).
pub fn check_mudlib(root: &Path) -> std::io::Result<MudlibReport> {
    let mut files = Vec::new();
    collect_wf(root, root, &mut files)?;
    files.sort();
    let mut s = Session::new(FsLoader {
        root: root.to_path_buf(),
    });
    for f in &files {
        s.compile(f);
    }
    let (outcomes, warnings_by_path) = s.into_outcomes_and_warnings();
    let mut programs = BTreeMap::new();
    let mut errors = Vec::new();
    for (path, o) in outcomes {
        match o {
            Outcome::Ok(c) => {
                programs.insert(path, c);
            }
            Outcome::Failed(r) | Outcome::Missing(r) => {
                // A missing file is only an error if someone inherits it;
                // that inheritor reports it with a span.
                if files.contains(&path) {
                    errors.push(r);
                }
            }
        }
    }
    let warnings = warnings_by_path.into_values().flatten().collect();
    Ok(MudlibReport {
        programs,
        errors,
        warnings,
    })
}

fn collect_wf(root: &Path, dir: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            collect_wf(root, &p, out)?;
        } else if p.extension().is_some_and(|e| e == "wf")
            && let Ok(rel) = p.strip_prefix(root)
        {
            let rel = rel.with_extension("");
            let s = rel.to_string_lossy().replace('\\', "/");
            out.push(format!("/{s}"));
        }
    }
    Ok(())
}

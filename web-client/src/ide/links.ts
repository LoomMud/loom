// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * M-IDE-2 (OBI-179 threat model v2 §5): the *only* URLs the IDE will
 * turn into a clickable link are `https:` and the virtual-filesystem
 * scheme it uses for mudlib references, `loom-vfs:`.
 *
 * Why a scheme allow-list rather than a block-list: the strings that end
 * up here are compiler diagnostics, LSP hover markdown, and doc comments
 * -- all builder-controlled. `javascript:` is the classic one, but
 * `data:text/html`, `blob:`, `file:`, and a `<base>`-relative `//host`
 * are all equally reachable the moment someone writes them into a
 * comment, and the staff origin holds a live session cookie. A deny-list
 * written against today's browser is a slow, one-way ratchet; a
 * two-scheme allow-list is checked once, here, and every renderer that
 * wants to make a link calls [`sanitizeLinkUrl`] first.
 *
 * This is not the only line of defence -- it is the one that has to be,
 * because Monaco's own link handling (`openerService`, and the
 * `editor.linkOpen` contribution) runs *inside* the editor's renderers
 * with no hook for a caller-supplied predicate. The belt to match:
 * `./editor.ts` disables Monaco's built-in document links
 * (`links: false`), registers a single `loom-vfs`/`https` link provider
 * that routes through this module, and hands hover/markdown rendering
 * `isTrusted: false` + `supportHtml: false` so a `<a href>` in a doc
 * comment never becomes markup at all (it renders as literal text).
 */

/** The mudlib-reference scheme: `loom-vfs:/cmds/kill.c` points at a file
 * in the tree this IDE is showing, and clicking one opens it locally. It
 * is deliberately not a real resolvable scheme -- nothing on the network
 * or filesystem can be reached with it, and the handler in `./app.ts`
 * only ever maps the path onto a `/api/v1/files/content` request the
 * driver already authorises. */
export const VFS_SCHEME = "loom-vfs:";

/** Schemes a link may use. `http:` is *not* in here: a cleartext
 * off-origin fetch from a page holding a session cookie is an
 * information-leak path, and the only reason to allow it would be a
 * local-doc link, which `loom-vfs:` exists to serve. */
export const ALLOWED_LINK_SCHEMES: readonly string[] = ["https:", VFS_SCHEME];

/**
 * Return `url` if clicking it is safe, `null` if it is not.
 *
 * Accepted forms:
 *  - `https:<anything>` with a non-empty host and no embedded
 *    credentials (`https://user:pass@host/` is a phishing staple and a
 *    cookie-confusing one).
 *  - `loom-vfs:/<mudlib path>` -- absolute, no query/fragment/host
 *    component, no `\` (Windows-style path confusion), and no percent
 *    encoding at all: the path is spliced into a `/api/v1/files/*`
 *    request *after* `encodeURIComponent`, so a pre-encoded `%2e%2e`
 *    here would double-encode into a literal filename rather than a
 *    traversal, and rejecting it keeps the two layers honest (M-FS-2's
 *    resolver is still the authority; this is the IDE refusing to even
 *    offer the click).
 *
 * Everything else -- no scheme, `javascript:`, `data:`, `blob:`, `file:`,
 * `//host`, a malformed URL -- is `null`. A relative URL is rejected
 * rather than resolved because the base it would resolve against is this
 * page's own origin, and a builder-authored "docs" link that turns into
 * `GET /api/v1/admin/...` with a session attached is not a feature.
 */
export function sanitizeLinkUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const schemeEnd = trimmed.indexOf(":");
  if (schemeEnd <= 0) {
    return null;
  }
  // A raw `\\` is not legal in a URL, but browsers *do* rewrite it into a
  // path or even an authority separator (`https:/\/\/host` becomes
  // `https://host`), which is exactly the confusion this filter exists to
  // refuse: the string a builder wrote must mean the same thing here and
  // in the address bar.
  if (trimmed.includes("\\")) {
    return null;
  }
  const scheme = trimmed.slice(0, schemeEnd + 1).toLowerCase();
  if (!ALLOWED_LINK_SCHEMES.includes(scheme)) {
    return null;
  }
  if (scheme === VFS_SCHEME) {
    return isVfsPath(trimmed.slice(schemeEnd + 1)) ? trimmed : null;
  }
  return isPlainHttps(trimmed) ? trimmed : null;
}

/** `loom-vfs:`'s authority: a `/`-prefixed mudlib path and nothing else. */
function isVfsPath(rest: string): boolean {
  if (!rest.startsWith("/")) {
    return false;
  }
  if (rest.startsWith("//")) {
    return false; // an authority -- `loom-vfs://host/path` has no meaning here
  }
  if (/[\\?#%]/.test(rest)) {
    return false;
  }
  // `..` segments are the driver's problem to refuse (M-FS-2's resolver
  // canonicalizes and confines), but a link that contains one is a link
  // the IDE should not offer: it can only ever 404, and its presence is
  // a sign the text was crafted.
  return !rest.split("/").includes("..");
}

function isPlainHttps(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") {
    return false;
  }
  // Reject on the string, not just on `parsed.username`: `https://@host/`
  // parses to an *empty* username and still routes through an authority
  // with credentials, which is the phishing form we care about.
  if (url.includes("@")) {
    return false;
  }
  if (parsed.hostname.length === 0 || !parsed.hostname.includes(".")) {
    return false;
  }
  return true;
}

/** The Markdown link/image syntax that can appear in a doc comment or a
 * diagnostic: `[text](url)`, `![alt](url)`, or a bare `<url>`. Only
 * used to *find* candidate URLs for [`sanitizeLinkUrl`] -- the actual
 * rendering path strips markup rather than interpreting it (see
 * `./editor.ts`'s `supportHtml: false`), so a matched span here becomes
 * a Monaco document link, never an `<a>` element. */
export function linkCandidates(text: string): string[] {
  const seen = new Set<string>();
  const push = (value: string | undefined): void => {
    if (value !== undefined) seen.add(value);
  };
  for (const match of text.matchAll(/!?\[[^\]]*\]\(\s*<?([^\s)>]+)>?[^)]*\)/g)) {
    push(match[1]);
  }
  for (const match of text.matchAll(/<((?:https|loom-vfs):[^>]*)>/g)) {
    push(match[1]);
  }
  // A bare url is found by *both* the markdown pass and this one when a
  // doc comment writes `[text](https://…)` with no space, hence the Set:
  // a provider registering the same range twice makes Monaco underline it
  // twice and show two identical hovers.
  for (const match of text.matchAll(/\b((?:https|loom-vfs):\/\/?[^\s"'`)<>]+)/g)) {
    push(match[1]);
  }
  return [...seen];
}

/** The safe subset of candidates -- what a link provider may register. */
export function safeLinkUrls(text: string): string[] {
  const urls: string[] = [];
  for (const candidate of linkCandidates(text)) {
    const safe = sanitizeLinkUrl(candidate);
    if (safe !== null && !urls.includes(safe)) {
      urls.push(safe);
    }
  }
  return urls;
}

/** Strip Markdown/HTML markup from a hover/diagnostic string so it can
 * only ever be shown as text (M-IDE-2: no HTML sink in the IDE's
 * rendering path). Deliberately crude: it removes tag-looking runs and
 * escapes nothing because nothing is interpreted -- the caller assigns
 * the result to `textContent`. */
export function asPlainText(text: string): string {
  return text.replace(/<\/?[a-zA-Z][^>]*>/g, "");
}

/** A `loom-vfs:` URL's mudlib path, for the click handler that opens it. */
export function vfsPathOf(url: string): string | null {
  if (!url.startsWith(VFS_SCHEME)) {
    return null;
  }
  const rest = url.slice(VFS_SCHEME.length);
  return isVfsPath(rest) ? rest : null;
}

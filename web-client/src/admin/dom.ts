// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * DOM-safe rendering helpers for every admin page (M-IDE-1/M-IDE-2): who
 * names, audit rows, error messages, and broadcast text are all
 * staff-/driver-controlled strings that must only ever reach the page
 * through `Node.textContent`/`document.createTextNode`, never through
 * `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or a template-literal
 * HTML string assigned to any of those. `el()` is the one place every
 * page module builds an element; nothing under `pages/` touches
 * `innerHTML` directly (enforced by `scripts/check-no-html-sinks.mjs`,
 * run in CI -- see that script's own doc comment).
 */

export type Children = (Node | string)[];

export function el(
  tag: string,
  attrs: Record<string, string> = {},
  children: Children = [],
): HTMLElement {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, value);
  }
  for (const child of children) {
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(container: HTMLElement): void {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }
}

/** Renders `rows` as a `<table>` with a header row from `columns`'
 * labels -- every cell's content goes through `el()`'s text-node path,
 * so a value that happens to contain `<script>` is inert, displayed
 * literally. */
export function table<T>(
  columns: { label: string; render: (row: T) => string }[],
  rows: T[],
  emptyText = "(none)",
): HTMLElement {
  if (rows.length === 0) {
    return el("p", {}, [emptyText]);
  }
  const head = el(
    "tr",
    {},
    columns.map((c) => el("th", {}, [c.label])),
  );
  const body = rows.map((row) =>
    el(
      "tr",
      {},
      columns.map((c) => el("td", {}, [c.render(row)])),
    ),
  );
  return el("table", {}, [el("thead", {}, [head]), el("tbody", {}, body)]);
}

export function errorBanner(message: string): HTMLElement {
  return el("p", { class: "admin-error" }, [message]);
}

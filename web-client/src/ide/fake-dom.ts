// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A ~90-line stand-in for the DOM, enough for `src/admin/dom.ts`'s `el()`
 * /`clear()` and the IDE controller's own element touches to run under
 * `node:test` (OBI-180). Not a DOM implementation: it has no layout, no
 * events beyond a stored listener map, no parsing, and it deliberately
 * *refuses* to answer `innerHTML`/`outerHTML`/`insertAdjacentHTML` -- a
 * test that reached for those would fail here as well as in ESLint's
 * `no-unsanitized` gate (M-IDE-2).
 *
 * Installed by `./dom-globals.ts` as `globalThis.document` for the
 * duration of a test file.
 */

export class FakeText {
  nodeType = 3;
  parentNode: FakeElement | null = null;
  data: string;
  constructor(data: string) {
    this.data = data;
  }
  get textContent(): string {
    return this.data;
  }
}

export class FakeElement {
  nodeType = 1;
  readonly tagName: string;
  readonly children: (FakeElement | FakeText)[] = [];
  readonly attributes = new Map<string, string>();
  readonly listeners = new Map<string, (() => void)[]>();
  parentNode: FakeElement | null = null;
  textContent = "";
  disabled = false;

  constructor(tagName: string) {
    this.tagName = tagName;
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }

  append(...nodes: (FakeElement | FakeText | string)[]): void {
    for (const node of nodes) {
      const child = typeof node === "string" ? new FakeText(node) : node;
      child.parentNode = this;
      this.children.push(child);
    }
  }

  get firstChild(): FakeElement | FakeText | null {
    return this.children[0] ?? null;
  }

  removeChild(child: FakeElement | FakeText): void {
    const index = this.children.indexOf(child);
    if (index < 0) {
      throw new Error("removeChild: not a child");
    }
    this.children.splice(index, 1);
    child.parentNode = null;
  }

  remove(): void {
    this.parentNode?.removeChild(this);
  }

  addEventListener(type: string, handler: () => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(handler);
    this.listeners.set(type, list);
  }

  /** Fire a stored listener -- the test's "click". */
  click(): void {
    for (const handler of this.listeners.get("click") ?? []) {
      handler();
    }
  }

  /** The rendered text, depth-first, for assertions. */
  get text(): string {
    const parts: string[] = [];
    if (this.textContent.length > 0) {
      parts.push(this.textContent);
    }
    for (const child of this.children) {
      parts.push(child instanceof FakeText ? child.data : child.text);
    }
    return parts.join("");
  }

  find(tagName: string): FakeElement[] {
    const out: FakeElement[] = [];
    for (const child of this.children) {
      if (child instanceof FakeElement) {
        if (child.tagName === tagName) out.push(child);
        out.push(...child.find(tagName));
      }
    }
    return out;
  }
}

export class FakeDocument {
  readonly elements = new Map<string, FakeElement>();

  createElement(tagName: string): FakeElement {
    return new FakeElement(tagName);
  }

  createTextNode(data: string): FakeText {
    return new FakeText(data);
  }

  getElementById(id: string): FakeElement | null {
    return this.elements.get(id) ?? null;
  }
}

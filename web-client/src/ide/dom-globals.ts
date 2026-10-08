// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

import { FakeDocument, FakeElement } from "./fake-dom.js";

/** Install the test DOM. Called from a test file's top level, before any
 * module that touches `document` is exercised. */
export function installFakeDom(): { document: FakeDocument; byId: (id: string) => FakeElement } {
  const document = new FakeDocument();
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    writable: true,
    value: document,
  });
  const byId = (id: string): FakeElement => {
    let element = document.elements.get(id);
    if (element === undefined) {
      element = new FakeElement("div");
      element.setAttribute("id", id);
      document.elements.set(id, element);
    }
    return element;
  };
  return { document, byId };
}

/** Read a DOM-typed node back as the fake it actually is, so a test can
 * assert on `text`/`find` without re-casting at every call site. */
export function asFake(node: HTMLElement): FakeElement {
  return node as unknown as FakeElement;
}

export { FakeElement, FakeText } from "./fake-dom.js";

import { describe, expect, it } from "vitest";

import { decode, encode } from "./crypto";

describe("browser protocol encoding", () => {
  it("round trips unpadded base64url without unsafe characters", () => {
    const source = Uint8Array.from([0, 1, 2, 127, 128, 250, 255]);
    const encoded = encode(source);
    expect(encoded).not.toMatch(/[+/=]/u);
    expect(decode(encoded)).toEqual(source);
  });
});

import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  encode,
  pairingVerificationCode,
  secureAad,
  secureContext,
  secureRequestSignatureInput,
} from "./crypto";

interface ProtocolVectors {
  secure_request: {
    version: number;
    pair_id: string;
    request_id: string;
    sequence: number;
    created_at: number;
    ephemeral_public_key: string;
    nonce: string;
    ciphertext: string;
  };
  secure_context: string;
  secure_aad_request_base64url: string;
  secure_signature_input: string;
  pairing_shared_utf8: string;
  pairing_transcript_utf8: string;
  pairing_verification_code: string;
}

const vectors = JSON.parse(
  readFileSync(
    path.resolve(
      process.cwd(),
      "../../tests/browser-extension/protocol-v1-vectors.json",
    ),
    "utf8",
  ),
) as ProtocolVectors;

describe("protocol V1 cross-implementation vectors", () => {
  it("keeps context, AAD and signature bytes identical to Rust", () => {
    const request = vectors.secure_request;
    expect(
      secureContext(request.pair_id, request.sequence, request.request_id),
    ).toBe(vectors.secure_context);
    expect(
      encode(
        secureAad(
          request.pair_id,
          request.sequence,
          request.request_id,
          "request",
        ),
      ),
    ).toBe(vectors.secure_aad_request_base64url);
    expect(new TextDecoder().decode(secureRequestSignatureInput(request))).toBe(
      vectors.secure_signature_input,
    );
  });

  it("derives the same human pairing code as Rust", async () => {
    const encoder = new TextEncoder();
    await expect(
      pairingVerificationCode(
        encoder.encode(vectors.pairing_shared_utf8),
        encoder.encode(vectors.pairing_transcript_utf8),
      ),
    ).resolves.toBe(vectors.pairing_verification_code);
  });
});

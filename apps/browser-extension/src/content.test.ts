import { beforeAll, describe, expect, it, vi } from "vitest";

type Listener = (
  message: {
    type: "staraxis_fill";
    origin: string;
    username: string;
    password: string;
    expiresAt: number;
  },
  sender: object,
  respond: (response: { ok: boolean; message: string }) => void,
) => void;

let listener: Listener | undefined;
const sendMessageMock = vi.fn();

beforeAll(async () => {
  vi.stubGlobal("chrome", {
    runtime: {
      lastError: undefined,
      onMessage: {
        addListener: (next: Listener) => {
          listener = next;
        },
      },
      sendMessage: sendMessageMock,
    },
  });
  await import("./content");
});

describe("top-level HTTPS form filling", () => {
  it("fills one visible login form and consumes the message values", () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="username" type="text" />
        <input autocomplete="current-password" type="password" />
      </form>
    `;
    for (const input of document.querySelectorAll("input")) {
      vi.spyOn(input, "getBoundingClientRect").mockReturnValue({
        width: 180,
        height: 32,
        top: 0,
        left: 0,
        right: 180,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      });
    }
    const message = {
      type: "staraxis_fill" as const,
      origin: "https://example.com",
      username: "alice@example.com",
      password: "correct horse battery staple",
      expiresAt: Date.now() + 10_000,
    };
    let response: { ok: boolean; message: string } | undefined;
    listener?.(message, {}, (value) => {
      response = value;
    });
    const inputs = document.querySelectorAll<HTMLInputElement>("input");
    expect(response?.ok).toBe(true);
    expect(inputs[0].value).toBe("alice@example.com");
    expect(inputs[1].value).toBe("correct horse battery staple");
    expect(message.username).toBe("");
    expect(message.password).toBe("");
  });

  it("rejects a mismatched origin before touching the fields", () => {
    const input = document.querySelector<HTMLInputElement>(
      'input[type="password"]',
    );
    const message = {
      type: "staraxis_fill" as const,
      origin: "https://example.com.evil.test",
      username: "mallory",
      password: "stolen",
      expiresAt: Date.now() + 10_000,
    };
    let response: { ok: boolean; message: string } | undefined;
    listener?.(message, {}, (value) => {
      response = value;
    });
    expect(response?.ok).toBe(false);
    expect(input?.value).toBe("correct horse battery staple");
  });

  it("rejects expired values and ambiguous password forms", () => {
    document.body.innerHTML = `
      <form>
        <input type="text" />
        <input type="password" />
        <input type="password" />
      </form>
    `;
    for (const input of document.querySelectorAll("input")) {
      vi.spyOn(input, "getBoundingClientRect").mockReturnValue({
        width: 180,
        height: 32,
        top: 0,
        left: 0,
        right: 180,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      });
    }
    let response: { ok: boolean; message: string } | undefined;
    listener?.(
      {
        type: "staraxis_fill",
        origin: "https://example.com",
        username: "alice",
        password: "secret",
        expiresAt: Date.now() + 10_000,
      },
      {},
      (value) => {
        response = value;
      },
    );
    expect(response?.ok).toBe(false);
    expect(response?.message).toContain("multiple password fields");

    listener?.(
      {
        type: "staraxis_fill",
        origin: "https://example.com",
        username: "alice",
        password: "secret",
        expiresAt: Date.now() - 1,
      },
      {},
      (value) => {
        response = value;
      },
    );
    expect(response?.ok).toBe(false);
    expect(
      document.querySelector<HTMLInputElement>('input[type="password"]')?.value,
    ).toBe("");
  });

  it("ignores hidden and off-screen decoy password fields", () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="username" type="text" />
        <input id="decoy" type="password" />
        <input id="real" type="password" />
      </form>
    `;
    for (const input of document.querySelectorAll("input")) {
      vi.spyOn(input, "getBoundingClientRect").mockReturnValue({
        width: 180,
        height: 32,
        top: 0,
        left: 0,
        right: 180,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      });
    }
    vi.spyOn(
      document.querySelector<HTMLInputElement>("#decoy")!,
      "getBoundingClientRect",
    ).mockReturnValue({
      width: 1,
      height: 1,
      top: -100,
      left: -100,
      right: -99,
      bottom: -99,
      x: -100,
      y: -100,
      toJSON: () => ({}),
    });
    let response: { ok: boolean; message: string } | undefined;
    listener?.(
      {
        type: "staraxis_fill",
        origin: "https://example.com",
        username: "alice",
        password: "secret",
        expiresAt: Date.now() + 10_000,
      },
      {},
      (value) => {
        response = value;
      },
    );
    expect(response?.ok).toBe(true);
    expect(document.querySelector<HTMLInputElement>("#decoy")?.value).toBe("");
    expect(document.querySelector<HTMLInputElement>("#real")?.value).toBe(
      "secret",
    );
  });

  it("captures one submitted HTTPS login without placing the password in the prompt DOM", () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="username" type="email" value="alice@example.com" />
        <input autocomplete="current-password" type="password" value="new secret" />
        <button type="submit">Sign in</button>
      </form>
    `;
    for (const input of document.querySelectorAll("input")) {
      vi.spyOn(input, "getBoundingClientRect").mockReturnValue({
        width: 180,
        height: 32,
        top: 0,
        left: 0,
        right: 180,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      });
    }
    let submitted: Record<string, unknown> | undefined;
    sendMessageMock.mockImplementation(
      (message: Record<string, unknown>, respond: (value: object) => void) => {
        submitted = { ...message };
        respond({
          kind: "save_prompt",
          captureId: "capture-one",
          origin: "https://example.com",
          username: "alice@example.com",
          action: "create",
        });
      },
    );

    document
      .querySelector("form")
      ?.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));

    expect(submitted).toMatchObject({
      type: "staraxis_login_submitted",
      origin: "https://example.com",
      username: "alice@example.com",
      password: "new secret",
    });
    const prompt = document.getElementById("staraxis-save-prompt");
    expect(prompt).not.toBeNull();
    expect(prompt?.textContent).not.toContain("new secret");
  });

  it("captures a scripted login triggered by an anchor inside the form", () => {
    document.body.innerHTML = `
      <form onsubmit="return false">
        <input autocomplete="off" name="username" type="text" value="mozhe-user" />
        <input autocomplete="off" name="password" type="password" value="mozhe-secret" />
        <a class="s btnBlue" href="#">登录</a>
        <a href="/forgot">忘记密码</a>
      </form>
    `;
    for (const input of document.querySelectorAll("input")) {
      vi.spyOn(input, "getBoundingClientRect").mockReturnValue({
        width: 180,
        height: 32,
        top: 0,
        left: 0,
        right: 180,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      });
    }
    let submitted: Record<string, unknown> | undefined;
    sendMessageMock.mockImplementation(
      (message: Record<string, unknown>, respond: (value: object) => void) => {
        submitted = { ...message };
        respond({
          kind: "save_prompt",
          captureId: "capture-mozhe",
          origin: "https://example.com",
          username: "mozhe-user",
          action: "create",
        });
      },
    );

    document
      .querySelector<HTMLAnchorElement>(".btnBlue")
      ?.dispatchEvent(
        new MouseEvent("click", { bubbles: true, button: 0, cancelable: true }),
      );

    expect(submitted).toMatchObject({
      type: "staraxis_login_submitted",
      origin: "https://example.com",
      username: "mozhe-user",
      password: "mozhe-secret",
    });
    expect(document.getElementById("staraxis-save-prompt")).not.toBeNull();
  });

  it("waits for a successful form transition before showing the save prompt", async () => {
    document.getElementById("staraxis-save-prompt")?.remove();
    document.body.innerHTML = `
      <form>
        <input autocomplete="username" type="email" value="new@example.com" />
        <input autocomplete="current-password" type="password" value="new secret" />
        <button type="submit">Sign in</button>
      </form>
    `;
    for (const input of document.querySelectorAll("input")) {
      vi.spyOn(input, "getBoundingClientRect").mockReturnValue({
        width: 180,
        height: 32,
        top: 0,
        left: 0,
        right: 180,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      });
    }
    const messages: Record<string, unknown>[] = [];
    sendMessageMock.mockImplementation(
      (message: Record<string, unknown>, respond: (value: object) => void) => {
        messages.push({ ...message });
        respond(
          message.type === "staraxis_login_outcome"
            ? {
                kind: "save_prompt",
                captureId: "after-success",
                origin: "https://example.com",
                username: "new@example.com",
                action: "create",
              }
            : { kind: "none" },
        );
      },
    );

    document
      .querySelector("form")
      ?.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));
    expect(document.getElementById("staraxis-save-prompt")).toBeNull();

    document.querySelector("form")?.remove();
    await new Promise((resolve) => window.setTimeout(resolve, 1_000));

    expect(messages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "staraxis_login_outcome",
          outcome: "success",
        }),
      ]),
    );
    expect(document.getElementById("staraxis-save-prompt")).not.toBeNull();
  });

  it("captures matching new-password and confirmation fields on registration", () => {
    document.getElementById("staraxis-save-prompt")?.remove();
    document.body.innerHTML = `
      <form>
        <input autocomplete="email" type="email" value="join@example.com" />
        <input autocomplete="new-password" type="password" value="registration secret" />
        <input autocomplete="new-password" type="password" value="registration secret" />
        <button type="submit">Create account</button>
      </form>
    `;
    for (const input of document.querySelectorAll("input")) {
      vi.spyOn(input, "getBoundingClientRect").mockReturnValue({
        width: 180,
        height: 32,
        top: 0,
        left: 0,
        right: 180,
        bottom: 32,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      });
    }
    let submitted: Record<string, unknown> | undefined;
    sendMessageMock.mockImplementation(
      (message: Record<string, unknown>, respond: (value: object) => void) => {
        submitted = { ...message };
        respond({
          kind: "save_prompt",
          captureId: "registration",
          origin: "https://example.com",
          username: "join@example.com",
          action: "create",
        });
      },
    );

    document
      .querySelector("form")
      ?.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));

    expect(submitted).toMatchObject({
      type: "staraxis_login_submitted",
      username: "join@example.com",
      password: "registration secret",
    });
  });
});

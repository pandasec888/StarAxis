export interface ClipboardLease {
  value: string;
  expiresAt: number;
}

export async function copyWithConditionalClear(
  value: string,
  clearSeconds: number,
): Promise<ClipboardLease> {
  await navigator.clipboard.writeText(value);
  return {
    value,
    expiresAt: Date.now() + clearSeconds * 1_000,
  };
}

export async function clearClipboardIfUnchanged(
  lease: ClipboardLease | null,
): Promise<boolean> {
  if (
    !lease ||
    !navigator.clipboard?.readText ||
    !navigator.clipboard?.writeText
  )
    return false;
  try {
    if ((await navigator.clipboard.readText()) !== lease.value) return false;
    await navigator.clipboard.writeText("");
    return true;
  } catch {
    return false;
  }
}

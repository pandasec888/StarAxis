import { useCallback, useEffect, useState } from "react";

import {
  DEFAULT_EXTENSION_LOCALE,
  EXTENSION_LOCALE_KEY,
  parseExtensionLocale,
  readExtensionLocale,
  writeExtensionLocale,
  type ExtensionLocale,
} from "./locale";

export function useExtensionLocale(): [
  ExtensionLocale,
  (locale: ExtensionLocale) => void,
] {
  const [locale, setLocaleState] = useState<ExtensionLocale>(
    DEFAULT_EXTENSION_LOCALE,
  );

  useEffect(() => {
    readExtensionLocale(setLocaleState);
    if (!chrome.storage?.onChanged) return;
    const onChanged = (
      changes: Record<string, chrome.storage.StorageChange>,
      areaName: string,
    ) => {
      if (areaName !== "local") return;
      const changed = changes[EXTENSION_LOCALE_KEY];
      if (changed) setLocaleState(parseExtensionLocale(changed.newValue));
    };
    chrome.storage.onChanged.addListener(onChanged);
    return () => chrome.storage.onChanged.removeListener(onChanged);
  }, []);

  const setLocale = useCallback((next: ExtensionLocale) => {
    setLocaleState(next);
    writeExtensionLocale(next);
  }, []);

  return [locale, setLocale];
}

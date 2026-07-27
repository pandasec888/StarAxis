import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { TrayUnlock } from "./TrayUnlock";
import "./tray-unlock.css";

const root = document.getElementById("root");

if (root === null) {
  throw new Error("missing tray unlock root");
}

createRoot(root).render(
  <StrictMode>
    <TrayUnlock />
  </StrictMode>,
);

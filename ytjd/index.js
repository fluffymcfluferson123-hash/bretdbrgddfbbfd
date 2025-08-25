// index.js (ESM shim)
import("./index.cjs").catch((err) => {
  console.error("Failed to load CJS server:", err)
})

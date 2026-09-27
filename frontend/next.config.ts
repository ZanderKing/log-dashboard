import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontendRoot = path.dirname(fileURLToPath(import.meta.url));

// Production is a static export served by FastAPI; no Node.js server features
// (rewrites, server actions, dynamic image optimization) may be added here.
const nextConfig: NextConfig = {
  output: "export",
  // A package lock exists higher in this workstation's home directory. Pinning
  // the trace root prevents Next.js from scanning outside this project.
  outputFileTracingRoot: frontendRoot,
  images: {
    unoptimized: true,
  },
};

export default nextConfig;

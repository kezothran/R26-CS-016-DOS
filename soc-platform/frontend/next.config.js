/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Slim production image (Dockerfile): bundles only the traced dependencies instead of all of
  // node_modules, which is what makes a multi-stage Docker build practical here.
  output: "standalone",
};

module.exports = nextConfig;

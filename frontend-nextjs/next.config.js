/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  env: {
    BACKEND_URL: process.env.BACKEND_URL || 'http://localhost:9100',
  },
  // Removed rewrites - using API routes as proxy instead
};

module.exports = nextConfig;


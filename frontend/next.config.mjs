/** @type {import('next').NextConfig} */
const nextConfig = {
  // Webpack configuration for 3D graph dependencies
  webpack: (config, { isServer }) => {
    // Ensure three.js and force-graph are only bundled client-side
    if (isServer) {
      config.externals = config.externals || [];
      // Don't bundle heavy 3D libs on server
      config.externals.push({
        "react-force-graph-3d": "react-force-graph-3d",
        "react-force-graph-2d": "react-force-graph-2d",
        three: "three",
        "three-spritetext": "three-spritetext",
      });
    }
    return config;
  },
  // Environment variables available at runtime (server-side API routes)
  env: {
    NEO4J_URI: process.env.NEO4J_URI || "bolt://localhost:7687",
    NEO4J_USER: process.env.NEO4J_USER || "neo4j",
    NEO4J_PASSWORD: process.env.NEO4J_PASSWORD || "changeme123",
    BACKEND_URL: process.env.BACKEND_URL || "http://localhost:8000",
  },
};

export default nextConfig;

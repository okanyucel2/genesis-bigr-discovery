#!/usr/bin/env bash
set -e

echo "=== Render Build Start ==="
echo "Node: $(node --version)"
echo "npm: $(npm --version)"
echo "PWD: $(pwd)"
echo "VITE_DEMO_MODE: $VITE_DEMO_MODE"

# Strip workspace:* devDependencies that only exist in monorepo context
echo "=== Stripping workspace deps ==="
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const removed = [];
for (const key in pkg.devDependencies) {
  if (pkg.devDependencies[key].includes('workspace:')) {
    removed.push(key);
    delete pkg.devDependencies[key];
  }
}
console.log('Removed:', removed.join(', '));
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
"

echo "=== npm install ==="
npm install 2>&1

echo "=== vite build (no sourcemaps for Render) ==="
VITE_DEMO_MODE=true npx vite build --sourcemap false 2>&1

echo "=== Build complete ==="
ls -la dist/

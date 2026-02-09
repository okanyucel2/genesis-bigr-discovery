#!/usr/bin/env bash
set -e

# Strip workspace:* devDependencies that only exist in monorepo context
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
for (const key in pkg.devDependencies) {
  if (pkg.devDependencies[key].includes('workspace:')) {
    delete pkg.devDependencies[key];
  }
}
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
"

npm install
npx vite build

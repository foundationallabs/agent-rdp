#!/usr/bin/env node

/**
 * Replace `workspace:*` dependency specs in a package.json with the sibling workspace
 * package's exact version. `npm publish` does not do this (only pnpm does), and a published
 * `workspace:*` spec cannot be installed.
 *
 * Usage:
 *   node scripts/resolve-workspace-deps.cjs <package-dir>
 */

const { readFileSync, readdirSync, writeFileSync, existsSync } = require('fs');
const { join, resolve } = require('path');

const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies'];

const packageDir = process.argv[2];
if (!packageDir) {
  console.error('Usage: node scripts/resolve-workspace-deps.cjs <package-dir>');
  process.exit(1);
}

const packagesRoot = join(__dirname, '..', 'packages');
const versions = new Map();
for (const entry of readdirSync(packagesRoot)) {
  const manifest = join(packagesRoot, entry, 'package.json');
  if (!existsSync(manifest)) continue;
  const { name, version } = JSON.parse(readFileSync(manifest, 'utf8'));
  versions.set(name, version);
}

const manifestPath = join(resolve(packageDir), 'package.json');
const pkg = JSON.parse(readFileSync(manifestPath, 'utf8'));

for (const field of DEP_FIELDS) {
  for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
    if (!spec.startsWith('workspace:')) continue;
    const version = versions.get(name);
    if (!version) {
      console.error(`${field}.${name} uses ${spec} but no workspace package has that name`);
      process.exit(1);
    }
    pkg[field][name] = version;
    console.log(`${field}.${name}: ${spec} -> ${version}`);
  }
}

writeFileSync(manifestPath, JSON.stringify(pkg, null, 2) + '\n');

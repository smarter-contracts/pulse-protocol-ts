/**
 * Table tests for the `covers` scope check.
 *
 * Mirrors pulse-protocol-go/types/payloads/feedpermission/scope_test.go —
 * keep the two case tables in sync.
 */

import { describe, expect, it } from 'vitest';
import type { FeedPermissionPayload } from '../payloads.js';
import { covers } from '../scope.js';

/** A payload granting `permissions` over `containerPath`; other fields are irrelevant. */
function scopedPayload(containerPath: string, permissions: string[]): FeedPermissionPayload {
  return {
    consentNo: 0,
    walletId: '',
    grantorWebId: '',
    counterpartyDid: '',
    feedType: '',
    podContainerPath: containerPath,
    permissions,
    dataCategories: [],
    issuedAt: 0,
    expiresAt: 0,
    encryptedNotary: new Uint8Array(),
    notaryKey1: new Uint8Array(),
    notaryKey2: new Uint8Array(),
  };
}

type Case = [
  name: string,
  container: string,
  grants: string[],
  action: string,
  target: string,
  want: boolean,
];

// Abbreviations keep one case per line, mirroring the Go table.
const CRED = 'pulse/credentials/';
const IDENT = 'pulse/credentials/identity/';
const W = ['write'];

const cases: Case[] = [
  // Action membership
  ['granted action', IDENT, W, 'write', 'pulse/credentials/identity/vc.ttl', true],
  ['action not granted', IDENT, ['read'], 'write', 'pulse/credentials/identity/vc.ttl', false],
  ['one of several granted modes', CRED, ['read', 'append'], 'append', 'pulse/credentials/x', true],
  ['action outside the vocabulary', CRED, ['delete'], 'delete', 'pulse/credentials/x', false],
  ['empty action', CRED, W, '', 'pulse/credentials/x', false],
  ['action casing must match', CRED, W, 'WRITE', 'pulse/credentials/x', false],
  ['no permissions granted', CRED, [], 'read', 'pulse/credentials/x', false],

  // Containment
  ['nested resource', CRED, W, 'write', 'pulse/credentials/identity/vc.ttl', true],
  ['the container itself', CRED, W, 'write', 'pulse/credentials/', true],
  ['the container itself without trailing slash', CRED, W, 'write', 'pulse/credentials', true],
  ['sibling container', CRED, W, 'write', 'pulse/feeds/x', false],
  ['parent of the container', IDENT, W, 'write', 'pulse/credentials/', false],

  // Prefix confusion
  ['prefix-confusable sibling', CRED, W, 'write', 'pulse/credentialsX/y', false],
  ['prefix-confusable leaf', CRED, W, 'write', 'pulse/credentialsX', false],
  ['prefix-confusable deep segment', IDENT, W, 'write', 'pulse/credentials/identityX/x', false],

  // Trailing-slash normalisation
  ['container without trailing slash', 'pulse/credentials', W, 'write', `${CRED}x`, true],
  ['target with trailing slash', CRED, W, 'write', 'pulse/credentials/identity/', true],

  // Path traversal and malformed targets
  ['parent traversal in target', CRED, W, 'write', 'pulse/credentials/../feeds/x', false],
  ['leading traversal in target', CRED, W, 'write', '../pulse/credentials/x', false],
  ['absolute target', CRED, W, 'write', '/pulse/credentials/x', false],
  ['empty target', CRED, W, 'write', '', false],
  ['empty segment in target', CRED, W, 'write', 'pulse//credentials/x', false],
  ['dot segment in target', CRED, W, 'write', 'pulse/./credentials/x', false],
  ['target is a bare slash', CRED, W, 'write', '/', false],

  // Container path validity
  ['container outside pulse', 'credentials/identity/', W, 'write', 'credentials/identity/x', false],
  ['container is the whole pulse tree', 'pulse/', W, 'write', 'pulse/credentials/x', false],
  ['container is pulse without slash', 'pulse', W, 'write', 'pulse/credentials/x', false],
  ['container is empty', '', W, 'write', 'pulse/credentials/x', false],
  ['container is absolute', '/pulse/credentials/', W, 'write', '/pulse/credentials/x', false],
  ['container has traversal', 'pulse/credentials/../feeds/', W, 'write', 'pulse/feeds/x', false],
  ['container root is pulse-like', 'pulseX/creds/', W, 'write', 'pulseX/creds/x', false],
];

describe('covers', () => {
  it.each(cases)('%s', (_name, container, grants, action, target, want) => {
    expect(covers(scopedPayload(container, grants), action, target)).toBe(want);
  });

  it('ignores expiry — liveness belongs to the enforcing service', () => {
    const p = scopedPayload(CRED, W);
    p.issuedAt = 1;
    p.expiresAt = 2; // long expired
    expect(covers(p, 'write', 'pulse/credentials/x')).toBe(true);
  });
});

/**
 * Scope checking for inbound feed permissions.
 *
 * Mirrors pulse-protocol-go/types/payloads/feedpermission/scope.go.
 */

import type { FeedPermissionPayload } from './payloads.js';

/**
 * Access modes that may appear in FeedPermissionPayload.permissions. Any other
 * value is not a recognised access mode and never grants access.
 */
export const ACTION_READ = 'read';
export const ACTION_WRITE = 'write';
export const ACTION_APPEND = 'append';

const ACTIONS: readonly string[] = [ACTION_READ, ACTION_WRITE, ACTION_APPEND];

/**
 * The single top-level container beneath which every feed permission must sit.
 * A permission covering the pod root, or anything outside "pulse/", is refused.
 */
const POD_ROOT = 'pulse';

/**
 * Splits a pod-relative path into its segments, rejecting anything that cannot be
 * compared safely segment-by-segment. A single trailing slash is normalised away;
 * every other empty segment, as well as "." and "..", is refused rather than
 * resolved, so no traversal can be smuggled through.
 */
function pathSegments(path: string): string[] | null {
  if (path === '' || path.startsWith('/')) return null;
  const segments = path.split('/');
  if (segments.length > 1 && segments[segments.length - 1] === '') segments.pop();
  if (segments.length === 0) return null;
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..') return null;
  }
  return segments;
}

/**
 * Splits a granted container path into segments, requiring it to sit strictly
 * beneath "pulse/". Returns null if the path is malformed or too broad.
 */
function containerSegments(path: string): string[] | null {
  const segments = pathSegments(path);
  if (segments === null) return null;
  if (segments.length < 2 || segments[0] !== POD_ROOT) return null;
  return segments;
}

/**
 * Reports whether `action` is both a recognised access mode and present in the
 * payload's granted permissions. Matching is exact: access modes are lower-case
 * tokens, and a value that differs in case is not the same token.
 */
function grantsAction(p: FeedPermissionPayload, action: string): boolean {
  if (!ACTIONS.includes(action)) return false;
  return p.permissions.includes(action);
}

/**
 * Reports whether the permission `p` authorises `action` on `targetPath`.
 *
 * It answers scope questions only — whether the access mode was granted and
 * whether the target lies inside the granted container. Liveness (expiry,
 * on-chain revocation) and identity (is the caller really the bound feed
 * provider?) are deliberately excluded: the enforcing service owns those, and
 * folding them in here would make a pure check look like an authorisation
 * decision.
 *
 * Both paths are pod-relative, "/"-separated and must already be percent-decoded
 * by the caller; a URL-encoded traversal such as "%2e%2e" is not decoded here and
 * would simply be treated as an ordinary segment name.
 *
 * The check is segment-wise, so "pulse/credentials/" covers
 * "pulse/credentials/identity/vc.ttl" but not "pulse/credentialsX/y". Everything
 * unclear is refused: absolute paths, empty paths, "." or ".." segments, empty
 * segments, container paths outside "pulse/", and a container path that is the
 * "pulse/" root itself (too broad to be a meaningful grant).
 */
export function covers(p: FeedPermissionPayload, action: string, targetPath: string): boolean {
  if (!grantsAction(p, action)) return false;
  const scope = containerSegments(p.podContainerPath);
  if (scope === null) return false;
  const target = pathSegments(targetPath);
  if (target === null) return false;
  if (target.length < scope.length) return false;
  return scope.every((segment, i) => target[i] === segment);
}

/**
 * Known-answer and validation tests for the v3 "cu" (custody) field on the
 * feed-permission payload (issue #783, VRS escrow-custody Phase 4).
 *
 * Every hex string and CID below is character-for-character the same constant as
 * in pulse-protocol-go/ipfs/cbor_feedpermission_custody_test.go. That is the
 * point of the file: byte-identical DAG-CBOR output between the two libraries is
 * a hard requirement, and these vectors are what prove it for the custody mark.
 *
 * Must be kept in sync with the Go file.
 */

import { CUSTODY_ESCROW, CUSTODY_HOLDER, type FeedPermissionPayload } from '@pulse-protocol/types';
import { describe, expect, it } from 'vitest';
import { marshalFeedPermission, unmarshalFeedPermission } from '../cbor-feedpermission.js';
import { getCid } from '../cid.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(h: string): Uint8Array {
  return Uint8Array.from((h.match(/../g) ?? []).map((x) => Number.parseInt(x, 16)));
}

function knownNotaryKey1(): Uint8Array {
  const k = new Uint8Array(33);
  k[0] = 0x02;
  return k;
}
function knownNotaryKey2(): Uint8Array {
  const k = new Uint8Array(33);
  k[0] = 0x03;
  return k;
}

// ── Fixtures — mirror knownV1Payload/knownV2Payload/knownV3Payload in Go ──────

const knownV1Cid = 'bafyreic6ntajpiaijirww2ghopyqyzccffrjv3h5h6r4nsgljiza7rcuia';

const knownV1Payload: FeedPermissionPayload = {
  consentNo: 42,
  walletId: 'wlt-canary-v1',
  grantorWebId: 'https://pod.example/alice/profile/card#me',
  counterpartyDid: 'did:web:feeds.example.com',
  feedType: 'open-banking',
  podContainerPath: 'pulse/feeds/open-banking/',
  permissions: ['read', 'write'],
  dataCategories: ['transaction-history', 'account-balance'],
  issuedAt: 1_700_000_000,
  expiresAt: 1_730_000_000,
  encryptedNotary: new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]),
  notaryKey1: knownNotaryKey1(),
  notaryKey2: knownNotaryKey2(),
};

const knownV2Payload: FeedPermissionPayload = {
  consentNo: 7,
  walletId: 'wlt-canary-v2',
  grantorWebId: 'https://pod.example/alice/profile/card#me',
  counterpartyDid: 'did:web:vc.example.com',
  feedType: 'verified-identity',
  podContainerPath: 'pulse/credentials/identity/',
  permissions: ['write'],
  dataCategories: ['identity-document'],
  dataDescription: 'Verified Identity Credential',
  issuedAt: 1_700_000_000,
  expiresAt: 1_730_000_000,
  encryptedNotary: new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]),
  notaryKey1: knownNotaryKey1(),
  notaryKey2: knownNotaryKey2(),
};

const knownV3Payload: FeedPermissionPayload = { ...knownV2Payload, previousCid: knownV1Cid };

// ── Expected wire vectors — identical to the Go constants ─────────────────────

const knownV1Hex =
  'af61746f666565642d7065726d697373696f6e61760162636e182a62646382737472616e73616374696f6e2d686973746f72796f6163636f756e742d62616c616e636562656e4501020304056266746c6f70656e2d62616e6b696e6762706d8264726561646577726974656363706478196469643a7765623a66656564732e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781970756c73652f66656564732f6f70656e2d62616e6b696e672f637769646d776c742d63616e6172792d76316467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d65';

const knownV2Hex =
  'b061746f666565642d7065726d697373696f6e61760262636e0762646381716964656e746974792d646f63756d656e74626464781c5665726966696564204964656e746974792043726564656e7469616c62656e4501020304056266747176657269666965642d6964656e7469747962706d8165777269746563637064766469643a7765623a76632e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781b70756c73652f63726564656e7469616c732f6964656e746974792f637769646d776c742d63616e6172792d76326467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d65';

const knownV3Hex =
  'b161746f666565642d7065726d697373696f6e61760362636e0762646381716964656e746974792d646f63756d656e74626464781c5665726966696564204964656e746974792043726564656e7469616c62656e4501020304056266747176657269666965642d6964656e7469747962706d8165777269746563637064766469643a7765623a76632e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781b70756c73652f63726564656e7469616c732f6964656e746974792f637769646d776c742d63616e6172792d76326467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d656470636964783b6261667972656963366e74616a706961696a697277773267686f707971797a63636666726a76336835683672346e73676c6a697a61377263756961';

/** The v1 canary marked "holder" — custody alone lifts a v1-shaped payload to v3. */
const knownV1HolderHex =
  'b061746f666565642d7065726d697373696f6e61760362636e182a62637566686f6c64657262646382737472616e73616374696f6e2d686973746f72796f6163636f756e742d62616c616e636562656e4501020304056266746c6f70656e2d62616e6b696e6762706d8264726561646577726974656363706478196469643a7765623a66656564732e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781970756c73652f66656564732f6f70656e2d62616e6b696e672f637769646d776c742d63616e6172792d76316467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d65';
const knownV1HolderCid = 'bafyreidtlihwrcaowycwtjjhtqa25m5xfw5bgc64bj4ao4tqzk4uj3ruka';

/** The v2 canary marked "escrow", carrying no previousCid. */
const knownV3CustodyHex =
  'b161746f666565642d7065726d697373696f6e61760362636e0762637566657363726f7762646381716964656e746974792d646f63756d656e74626464781c5665726966696564204964656e746974792043726564656e7469616c62656e4501020304056266747176657269666965642d6964656e7469747962706d8165777269746563637064766469643a7765623a76632e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781b70756c73652f63726564656e7469616c732f6964656e746974792f637769646d776c742d63616e6172792d76326467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d65';
const knownV3CustodyCid = 'bafyreid6karkqrcljgugkaqdjcdhellgymnc23pdxrqtpsxvykookhda2u';

/** Both v3 features at once — previousCid and custody. */
const knownV3BothHex =
  'b261746f666565642d7065726d697373696f6e61760362636e0762637566657363726f7762646381716964656e746974792d646f63756d656e74626464781c5665726966696564204964656e746974792043726564656e7469616c62656e4501020304056266747176657269666965642d6964656e7469747962706d8165777269746563637064766469643a7765623a76632e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781b70756c73652f63726564656e7469616c732f6964656e746974792f637769646d776c742d63616e6172792d76326467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d656470636964783b6261667972656963366e74616a706961696a697277773267686f707971797a63636666726a76336835683672346e73676c6a697a61377263756961';
const knownV3BothCid = 'bafyreicqmgcl44mmq7j5emh7elgxjy4yrgmc4fbzimnwduug4ac6s6mkki';

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('feed-permission custody known answers', () => {
  it('marshals a custody-only payload to the exact Go bytes', async () => {
    const block = marshalFeedPermission({ ...knownV2Payload, custody: CUSTODY_ESCROW });
    expect(toHex(block)).toBe(knownV3CustodyHex);
    expect(await getCid(block)).toBe(knownV3CustodyCid);
  });

  it('lifts a v1-shaped payload to v3 when it is marked, matching the Go bytes', async () => {
    const block = marshalFeedPermission({ ...knownV1Payload, custody: CUSTODY_HOLDER });
    expect(toHex(block)).toBe(knownV1HolderHex);
    expect(await getCid(block)).toBe(knownV1HolderCid);

    const got = unmarshalFeedPermission(block);
    expect(got.custody).toBe(CUSTODY_HOLDER);
  });

  it('composes custody with previousCid, matching the Go bytes', async () => {
    const block = marshalFeedPermission({ ...knownV3Payload, custody: CUSTODY_ESCROW });
    expect(toHex(block)).toBe(knownV3BothHex);
    expect(await getCid(block)).toBe(knownV3BothCid);
  });

  it('refuses to encode an unrecognised custody value', () => {
    // null and '' are included deliberately: only `undefined` means "unmarked",
    // so a laxer check would encode these as unmarked instead of reporting the
    // caller's mistake.
    for (const bad of ['Escrow', 'ESCROW', 'custodian', 'holder ', 'unknown', '', null]) {
      expect(() => marshalFeedPermission({ ...knownV2Payload, custody: bad as never })).toThrow(
        /custody/,
      );
    }
  });
});

describe('feed-permission custody does not disturb existing vectors', () => {
  it.each([
    ['v1', knownV1Payload, knownV1Hex],
    ['v2', knownV2Payload, knownV2Hex],
    ['v3 (previousCid only)', knownV3Payload, knownV3Hex],
  ])('leaves the %s canary bytes untouched', (_name, payload, hex) => {
    expect(toHex(marshalFeedPermission(payload as FeedPermissionPayload))).toBe(hex);
  });
});

describe('feed-permission custody decoding', () => {
  it.each([
    ['v1', knownV1Hex],
    ['v2', knownV2Hex],
    ['v3 (previousCid only)', knownV3Hex],
  ])('reads an absent mark on the %s canary as unmarked, never as holder', (_name, hex) => {
    const got = unmarshalFeedPermission(fromHex(hex));
    expect(got.custody).toBeUndefined();
    expect(got.custody).not.toBe(CUSTODY_HOLDER);
  });

  it.each([
    ['escrow', knownV3CustodyHex, CUSTODY_ESCROW],
    ['holder', knownV1HolderHex, CUSTODY_HOLDER],
    ['escrow with previousCid', knownV3BothHex, CUSTODY_ESCROW],
  ])('round-trips the %s mark', (_name, hex, want) => {
    expect(unmarshalFeedPermission(fromHex(hex)).custody).toBe(want);
  });

  it.each([1, 2])('rejects "cu" on a payload declaring version %i', (ver) => {
    // knownV1HolderHex carries no "dd", so no other version rule can fire first.
    const block = fromHex(knownV1HolderHex);
    const i = block.indexOf(0x61); // "v" key is 0x61 0x76
    const v = block.findIndex((b, k) => b === 0x61 && block[k + 1] === 0x76);
    expect(v).toBeGreaterThanOrEqual(0);
    expect(i).toBeGreaterThanOrEqual(0);
    expect(block[v + 2]).toBe(0x03);
    block[v + 2] = ver;
    expect(() => unmarshalFeedPermission(block)).toThrow(/cu/);
  });

  it.each(['ESCROW', 'custod', 'holdeR'])('rejects the unrecognised mark %s', (bad) => {
    // "escrow" and "holder" are both six characters, so a same-length substitution
    // keeps every CBOR length prefix valid and isolates the enum check.
    const block = fromHex(knownV3CustodyHex);
    const i = block.findIndex(
      (b, k) =>
        b === 0x62 && block[k + 1] === 0x63 && block[k + 2] === 0x75 && block[k + 3] === 0x66,
    );
    expect(i).toBeGreaterThanOrEqual(0);
    for (let k = 0; k < 6; k++) block[i + 4 + k] = bad.charCodeAt(k);
    expect(() => unmarshalFeedPermission(block)).toThrow(/custody/);
  });

  it('rejects a non-string "cu"', () => {
    const block = fromHex(knownV3CustodyHex);
    const i = block.findIndex(
      (b, k) =>
        b === 0x62 && block[k + 1] === 0x63 && block[k + 2] === 0x75 && block[k + 3] === 0x66,
    );
    expect(i).toBeGreaterThanOrEqual(0);
    // Replace text(6)"escrow" with the unsigned integer 7.
    const mangled = new Uint8Array([...block.slice(0, i + 3), 0x07, ...block.slice(i + 10)]);
    expect(() => unmarshalFeedPermission(mangled)).toThrow(/cu/);
  });
});

// ── Composition with policyVersions (#672) ────────────────────────────────────
//
// Custody (#783) and policyVersions (#672) are independent optional features of
// the same wire version — the coordination recorded in #672's design, Decision
// 6. These vectors mirror the Go ones in
// pulse-protocol-go/ipfs/cbor_feedpermission_custody_test.go exactly: "cu" keeps
// its position between "cn" and "dc", "pv" keeps its position after "pm", and
// neither displaces the other.

const knownPolicyHashPP = 'bafyreigmlkpf6fpxpupe3u44zypn4ey7tvnjw33mlhyqqv7qc5kpyfj4fq';
const knownPolicyHashTC = 'bafyreihmfpvga3o7mmryviquqppfuoe6tw75e22xywjgx7rr3njddnjtxq';

// Supplied out of docType order so the vectors also pin the encoder's sort.
const knownPolicyVersionsUnsorted = [
  { docType: 'terms-and-conditions', documentHash: knownPolicyHashTC },
  { docType: 'privacy-policy', documentHash: knownPolicyHashPP },
];

const knownV3CustodyPolicyHex =
  'b161746f666565642d7065726d697373696f6e61760362636e182a62637566686f6c64657262646382737472616e73616374696f6e2d686973746f72796f6163636f756e742d62616c616e636562656e4501020304056266746c6f70656e2d62616e6b696e6762706d82647265616465777269746562707682a2626468783b62616679726569676d6c6b70663666707870757065337534347a79706e3465793774766e6a7733336d6c6879717176377163356b7079666a3466716264746e707269766163792d706f6c696379a2626468783b62616679726569686d6670766761336f376d6d72797669717571707066756f6536747737356532327879776a6778377272336e6a64646e6a747871626474747465726d732d616e642d636f6e646974696f6e736363706478196469643a7765623a66656564732e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781970756c73652f66656564732f6f70656e2d62616e6b696e672f637769646d776c742d63616e6172792d76316467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d65';
const knownV3CustodyPolicyCid = 'bafyreiceby4u7ozz7tilaxzh7zrxol36lcthljjnf432qtzdoneyxmapeq';

// Every optional feature at once except "gx": the v2 "dd" plus all three v3
// features — "cu", "pv" and "pcid".
const knownV3AllFeaturesHex =
  'b361746f666565642d7065726d697373696f6e61760362636e0762637566657363726f7762646381716964656e746974792d646f63756d656e74626464781c5665726966696564204964656e746974792043726564656e7469616c62656e4501020304056266747176657269666965642d6964656e7469747962706d8165777269746562707682a2626468783b62616679726569676d6c6b70663666707870757065337534347a79706e3465793774766e6a7733336d6c6879717176377163356b7079666a3466716264746e707269766163792d706f6c696379a2626468783b62616679726569686d6670766761336f376d6d72797669717571707066756f6536747737356532327879776a6778377272336e6a64646e6a747871626474747465726d732d616e642d636f6e646974696f6e7363637064766469643a7765623a76632e6578616d706c652e636f6d636578701a671db480636961741a6553f100636e6b315821020000000000000000000000000000000000000000000000000000000000000000636e6b32582103000000000000000000000000000000000000000000000000000000000000000063706370781b70756c73652f63726564656e7469616c732f6964656e746974792f637769646d776c742d63616e6172792d76326467776964782968747470733a2f2f706f642e6578616d706c652f616c6963652f70726f66696c652f63617264236d656470636964783b6261667972656963366e74616a706961696a697277773267686f707971797a63636666726a76336835683672346e73676c6a697a61377263756961';
const knownV3AllFeaturesCid = 'bafyreiatnrqbvlpqd7utxmje4byzl6vlr2brymaihtswadlcp2yc2vctzq';

describe('feed-permission custody composes with policyVersions', () => {
  it('marshals custody + policyVersions to the exact Go bytes', async () => {
    const block = marshalFeedPermission({
      ...knownV1Payload,
      custody: CUSTODY_HOLDER,
      policyVersions: knownPolicyVersionsUnsorted,
    });
    expect(toHex(block)).toBe(knownV3CustodyPolicyHex);
    expect(await getCid(block)).toBe(knownV3CustodyPolicyCid);
  });

  it('marshals dd + cu + pv + pcid together to the exact Go bytes', async () => {
    const block = marshalFeedPermission({
      ...knownV3Payload,
      custody: CUSTODY_ESCROW,
      policyVersions: knownPolicyVersionsUnsorted,
    });
    expect(toHex(block)).toBe(knownV3AllFeaturesHex);
    expect(await getCid(block)).toBe(knownV3AllFeaturesCid);
  });

  it('round-trips every feature — neither v3 feature shadows the other', () => {
    const got = unmarshalFeedPermission(fromHex(knownV3AllFeaturesHex));
    expect(got.custody).toBe(CUSTODY_ESCROW);
    expect(got.previousCid).toBe(knownV1Cid);
    expect(got.dataDescription).toBe('Verified Identity Credential');
    expect(got.policyVersions).toEqual([
      { docType: 'privacy-policy', documentHash: knownPolicyHashPP },
      { docType: 'terms-and-conditions', documentHash: knownPolicyHashTC },
    ]);
  });
});

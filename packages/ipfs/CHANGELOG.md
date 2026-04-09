# Changelog — @pulse-protocol/ipfs

## [0.1.0] - 2026-04-09

### Added

- CIDv1 computation: `getCid` (DAG-CBOR codec, SHA2-256 multihash)
- V2 EC record CBOR encode/decode: `marshalConsentEc`, `unmarshalConsentEc`, `marshalRevokeEc`, `unmarshalRevokeEc`
- V2 PQ record CBOR encode/decode: `marshalConsentPq`, `unmarshalConsentPq`, `marshalRevokePq`, `unmarshalRevokePq`
- V1 EC record CBOR encode/decode: `marshalV1ConsentEc`, `unmarshalV1ConsentEc`, `marshalV1RevokeEc`, `unmarshalV1RevokeEc`
- V1 PQ record CBOR encode/decode: `marshalV1ConsentPq`, `unmarshalV1ConsentPq`, `marshalV1RevokePq`, `unmarshalV1RevokePq`

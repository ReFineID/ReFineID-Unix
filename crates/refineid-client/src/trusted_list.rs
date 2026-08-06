// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Authenticated EU trusted-list directory for qualified timestamp services.
//!
//! The European Commission's list of trusted lists (LOTL) names each current
//! national list and the exact certificates authorized to sign it. This module
//! authenticates the LOTL against the signer fingerprints published in
//! Official Journal notice C/2026/1944, authenticates every national list
//! against its signed pointer, and returns only identities of granted qualified
//! timestamp services.
//!
//! `XMLDSig` is constrained to the profiles in current EU lists. References are
//! same-document only, IDs must be globally unique, the sole enveloped
//! signature is a direct child of the TSL root, and readers descend from that
//! root through direct child steps. Content excluded by the enveloped transform
//! therefore cannot influence a directory answer.
//!
//! Authenticated sequence, issue-time, and document-digest metadata is retained
//! as an in-process rollback guard. It is intentionally not described as
//! restart-persistent: this module has no authenticated persistent state store.

use core::fmt;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use refineid_lib_core::text::Uri;
use refineid_lib_core::x509::{
    DateTime, MessageSignatureAlgorithm, OwnedCert, extract_basic_constraints, extract_key_usage,
};
use roxmltree::{Document, Node, NodeId, ParsingOptions};
use sha2::{Digest as _, Sha256, Sha512};
use xml_sec::c14n::{C14nAlgorithm, canonicalize};

use crate::{http, user_agent};

/// Where the European Commission publishes the list of trusted lists.
pub const EU_LIST_OF_LISTS: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

const MAX_LIST_BYTES: usize = 16_777_216;
/// Refuse a document whose conservative canonical-output estimate exceeds
/// this bound. The preflight counts source bytes, escaped expansion, and every
/// in-scope namespace on every emitted element before C14N allocates output.
const MAX_CANONICAL_BYTES: usize = 134_217_728;
const MAX_XML_NODES: u32 = 1_000_000;
const MAX_CONCURRENT_NATIONAL_LISTS: usize = 4;
const CACHE_LIFETIME: Duration = Duration::from_hours(1);
const FRESHNESS_SKEW: Duration = Duration::from_hours(1);
const MAX_SIGNATURE_BYTES: usize = 16_384;
const MAX_CERTIFICATE_BYTES: usize = 131_072;
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const TSL_NAMESPACE: &str = "http://uri.etsi.org/02231/v2#";
const DS_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES_NAMESPACE: &str = "http://uri.etsi.org/01903/v1.3.2#";
const TSL_ADDITIONAL_TYPES_NAMESPACE: &str = "http://uri.etsi.org/02231/v2/additionaltypes#";
const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_TRANSFORM: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const RSA_PSS_SHA256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
const RSA_PSS_PARAMETERS: &str = "http://www.w3.org/2021/04/xmldsig-more#rsa-pss";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
const MGF1_PARAMETERS: &str = "http://www.w3.org/2007/05/xmldsig-more#MGF1";
const QUALIFIED_TIMESTAMP_TYPE: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
const GRANTED_STATUS: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
const TRUSTED_LIST_MIME_TYPE: &str = "application/vnd.etsi.tsl+xml";
const PDF_MIME_TYPE: &str = "application/pdf";
const EU_GENERIC_TSL_TYPE: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";

/// SHA-256 fingerprints of the six LOTL-signing certificates in Official
/// Journal notice C/2026/1944 of 15 April 2026.
const OFFICIAL_JOURNAL_FINGERPRINTS: [&str; 6] = [
    "wGQcT31WxDGxySR0Lbf86cHu99f9ISETonaEhrOrzcU=",
    "4KYg+7Z0c2K7kzrEQWnWdqVTREcWz18xYF8SoiuDlrE=",
    "334pNgw0srjW1fQDJcHU0SyZIs7NM7dAdnSnSys8oeU=",
    "tj1BZ0TnCYv57CyqWWqTvCRo43+ChLpl7MBhcRvLqhg=",
    "I2ED8DqAMa6PR/kFm/jeOFZM2/6+3eSll9UPiYCqZTs=",
    "0gZP3XD2mC3MUWuG2dXFauqTlBfGJLLkeMCyneVPhHQ=",
];

/// One current granted qualified timestamp service identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedTimestampIdentity {
    /// Exact DER service-identity certificate, usable as a path anchor.
    pub certificate_der: Vec<u8>,
    /// Signed `StatusStartingTime` of the current granted service status.
    pub granted_from: DateTime,
}

/// Every authenticated granted qualified timestamp identity in the directory.
#[derive(Debug, Clone)]
pub struct TrustedTimestampIdentities {
    /// Current granted service identities and their signed status start times.
    pub identities: Vec<TrustedTimestampIdentity>,
    /// Whether every national list named by the LOTL was authenticated.
    /// Membership in an incomplete answer is proved; absence is not.
    pub is_complete: bool,
    /// Earliest signed `NextUpdate` across the LOTL and successful lists.
    pub valid_until: DateTime,
}

impl TrustedTimestampIdentities {
    /// Whether `certificate_der` was in a current granted service whose signed
    /// status had begun by `at`.
    #[must_use]
    pub fn contains_at(&self, certificate_der: &[u8], at: DateTime) -> bool {
        at < self.valid_until
            && self.identities.iter().any(|identity| {
                identity.certificate_der == certificate_der && at >= identity.granted_from
            })
    }
}

/// Why a trusted-list document or directory walk was unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedListError {
    /// XML or required XMLDSig/XAdES structure was malformed.
    Malformed,
    /// Duplicate IDs, an ambiguous target, or excluded unsigned content.
    Wrapping,
    /// A method was outside the constrained cryptographic profile.
    UnsupportedAlgorithm,
    /// A signed reference did not match its canonical target.
    InvalidDigest,
    /// No unique authorized certificate verified `SignatureValue`.
    InvalidSignature,
    /// The signer or signed `XAdES` certificate binding was unsuitable.
    InvalidSignerProfile,
    /// No embedded certificate was exactly authorized by the caller.
    UntrustedSigner,
    /// The signed issue/update window was invalid or not current.
    Stale,
    /// A lower sequence or inconsistent reuse followed a list already accepted
    /// by this process.
    Rollback,
    /// The authenticated LOTL named no current national XML list.
    EmptyDirectory,
    /// A response, pointer, or service identity could not be used.
    UnusableResponse,
    /// The short-lived cache mutex was poisoned by a panicking caller.
    CacheUnavailable,
}

impl fmt::Display for TrustedListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed trusted-list XML or XMLDSig",
            Self::Wrapping => "ambiguous or unsigned trusted-list content",
            Self::UnsupportedAlgorithm => "unsupported trusted-list signature profile",
            Self::InvalidDigest => "trusted-list reference digest mismatch",
            Self::InvalidSignature => "trusted-list signature verification failed",
            Self::InvalidSignerProfile => "invalid trusted-list signer profile",
            Self::UntrustedSigner => "trusted-list signer was not authorized",
            Self::Stale => "trusted list is outside its signed validity window",
            Self::Rollback => "trusted-list sequence rolled back or was reused inconsistently",
            Self::EmptyDirectory => "EU list of trusted lists contained no current XML list",
            Self::UnusableResponse => "trusted-list response was unusable",
            Self::CacheUnavailable => "trusted-list cache is unavailable",
        })
    }
}

impl core::error::Error for TrustedListError {}

#[derive(Debug, Clone)]
struct DirectoryRead {
    identities: TrustedTimestampIdentities,
    fetched_at: DateTime,
}

#[derive(Debug, Default)]
struct DirectoryCache {
    read: Option<DirectoryRead>,
    /// Highest authenticated metadata accepted for each list in this process.
    /// This map is not persisted across process restarts.
    versions: HashMap<String, SignedListVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedListPointer {
    location: Uri,
    signing_certificates: HashSet<Vec<u8>>,
    territory: Option<String>,
}

#[derive(Debug)]
struct NationalSuccess {
    identities: Vec<TrustedTimestampIdentity>,
    valid_until: DateTime,
}

#[derive(Clone, Copy)]
enum SignerTrust<'a> {
    Certificates(&'a HashSet<Vec<u8>>),
    Sha256Fingerprints(&'a HashSet<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedListVersion {
    sequence_number: u64,
    issued_at: DateTime,
    document_sha256: [u8; 32],
}

struct VerifiedDocument {
    next_update: DateTime,
    version: SignedListVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Sha256,
    Sha512,
}

impl DigestAlgorithm {
    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }

    const fn output_bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

struct SignerBinding {
    algorithm: DigestAlgorithm,
    certificate_digest: Vec<u8>,
    signing_time: DateTime,
}

struct Reference {
    algorithm: DigestAlgorithm,
    expected_digest: Vec<u8>,
    excludes_signature: bool,
    target: NodeId,
}

struct ParsedSignature {
    algorithm: MessageSignatureAlgorithm,
    binding: SignerBinding,
    certificates: Vec<Vec<u8>>,
    references: Vec<Reference>,
    signature_value: Vec<u8>,
    signature_node: NodeId,
    signed_info: NodeId,
}

static DIRECTORY_CACHE: OnceLock<Mutex<DirectoryCache>> = OnceLock::new();

/// Read the EU directory of granted qualified timestamp identities.
///
/// A complete result is cached for at most one hour and never beyond its
/// earliest signed `NextUpdate`. An incomplete result allows positive
/// membership proofs, but is never cached and cannot prove absence.
/// Authenticated version metadata also prevents rollback while this process
/// remains alive; it is not persisted across restarts.
///
/// # Errors
/// Returns [`TrustedListError`] when the LOTL cannot be fetched or
/// authenticated, contains no usable current national pointers, or its signed
/// validity window has closed.
pub fn qualified_timestamp_identities() -> Result<TrustedTimestampIdentities, TrustedListError> {
    let now = now_datetime()?;
    let cache = DIRECTORY_CACHE.get_or_init(|| Mutex::new(DirectoryCache::default()));
    {
        let stored = cache
            .lock()
            .map_err(|_ignored| TrustedListError::CacheUnavailable)?;
        if let Some(read) = stored.read.as_ref()
            && may_reuse(read, now)
        {
            return Ok(read.identities.clone());
        }
    }
    let fresh = fresh_timestamp_identities(now)?;
    let identities = fresh.identities.clone();
    let mut stored = cache
        .lock()
        .map_err(|_ignored| TrustedListError::CacheUnavailable)?;
    if identities.is_complete {
        stored.read = Some(fresh);
    } else {
        stored.read = None;
    }
    drop(stored);
    Ok(identities)
}

fn may_reuse(read: &DirectoryRead, now: DateTime) -> bool {
    let age_is_open = now
        .unix_duration()
        .checked_sub(read.fetched_at.unix_duration())
        .is_some_and(|age| age < CACHE_LIFETIME);
    age_is_open && now < read.identities.valid_until
}

fn fresh_timestamp_identities(now: DateTime) -> Result<DirectoryRead, TrustedListError> {
    let index_uri = Uri::parse(EU_LIST_OF_LISTS.to_owned())
        .map_err(|_ignored| TrustedListError::UnusableResponse)?;
    let index = fetch(&index_uri)?;
    let fingerprints = official_journal_fingerprints()?;
    let verified_index =
        verify_document(&index, SignerTrust::Sha256Fingerprints(&fingerprints), now)?;
    let pointers = trusted_list_pointers(&index)?;
    if pointers.is_empty() {
        return Err(TrustedListError::EmptyDirectory);
    }
    remember_verified_version(EU_LIST_OF_LISTS, &verified_index.version)?;

    let mut results = read_national_lists(&pointers, now);
    let failed: Vec<usize> = results
        .iter()
        .enumerate()
        .filter_map(|(index, result)| result.is_none().then_some(index))
        .collect();
    if !failed.is_empty() {
        let retry_pointers: Vec<TrustedListPointer> = failed
            .iter()
            .filter_map(|index| pointers.get(*index).cloned())
            .collect();
        let retried = read_national_lists(&retry_pointers, now);
        for (index, result) in failed.into_iter().zip(retried) {
            if let Some(slot) = results.get_mut(index) {
                *slot = result;
            }
        }
    }

    let mut identities_by_certificate: HashMap<Vec<u8>, DateTime> = HashMap::new();
    let mut complete = true;
    let mut valid_until = verified_index.next_update;
    for result in results {
        let Some(success) = result else {
            complete = false;
            continue;
        };
        for identity in success.identities {
            identities_by_certificate
                .entry(identity.certificate_der)
                .and_modify(|existing| *existing = (*existing).min(identity.granted_from))
                .or_insert(identity.granted_from);
        }
        valid_until = valid_until.min(success.valid_until);
    }
    if valid_until <= now {
        return Err(TrustedListError::UnusableResponse);
    }
    let mut identities: Vec<TrustedTimestampIdentity> = identities_by_certificate
        .into_iter()
        .map(|(certificate_der, granted_from)| TrustedTimestampIdentity {
            certificate_der,
            granted_from,
        })
        .collect();
    identities.sort_by(|left, right| left.certificate_der.cmp(&right.certificate_der));
    Ok(DirectoryRead {
        identities: TrustedTimestampIdentities {
            identities,
            is_complete: complete,
            valid_until,
        },
        fetched_at: now,
    })
}

/// Atomically compare and retain one authenticated list version.
///
/// This is process-local state only. A future persistent rollback guard needs
/// an authenticated application-state facility and is deliberately outside
/// this cache patch.
fn remember_verified_version(
    list: &str,
    candidate: &SignedListVersion,
) -> Result<(), TrustedListError> {
    let cache = DIRECTORY_CACHE.get_or_init(|| Mutex::new(DirectoryCache::default()));
    let mut stored = cache
        .lock()
        .map_err(|_ignored| TrustedListError::CacheUnavailable)?;
    accept_version(&mut stored.versions, list, candidate)
}

fn accept_version(
    versions: &mut HashMap<String, SignedListVersion>,
    list: &str,
    candidate: &SignedListVersion,
) -> Result<(), TrustedListError> {
    let Some(previous) = versions.get(list) else {
        versions.insert(list.to_owned(), candidate.clone());
        return Ok(());
    };
    if candidate.sequence_number < previous.sequence_number
        || candidate.issued_at < previous.issued_at
        || (candidate.sequence_number == previous.sequence_number && candidate != previous)
    {
        return Err(TrustedListError::Rollback);
    }
    if candidate.sequence_number > previous.sequence_number {
        versions.insert(list.to_owned(), candidate.clone());
    }
    Ok(())
}

fn read_national_lists(
    pointers: &[TrustedListPointer],
    now: DateTime,
) -> Vec<Option<NationalSuccess>> {
    let mut output = Vec::with_capacity(pointers.len());
    for chunk in pointers.chunks(MAX_CONCURRENT_NATIONAL_LISTS) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|pointer| scope.spawn(move || read_national_list(pointer, now).ok()))
                .collect();
            for handle in handles {
                output.push(handle.join().ok().flatten());
            }
        });
    }
    output
}

fn read_national_list(
    pointer: &TrustedListPointer,
    now: DateTime,
) -> Result<NationalSuccess, TrustedListError> {
    let encoded = fetch(&pointer.location)?;
    let verified = verify_document(
        &encoded,
        SignerTrust::Certificates(&pointer.signing_certificates),
        now,
    )?;
    validate_national_metadata(&encoded, pointer)?;
    let identities = qualified_timestamp_identities_in(&encoded, now)?;
    remember_verified_version(&pointer.location.to_string(), &verified.version)?;
    Ok(NationalSuccess {
        identities,
        valid_until: verified.next_update,
    })
}

fn validate_national_metadata(
    encoded: &[u8],
    pointer: &TrustedListPointer,
) -> Result<(), TrustedListError> {
    let document = parse_xml(encoded)?;
    let root = document.root_element();
    if !matches_name(root, "TrustServiceStatusList", Some(TSL_NAMESPACE)) {
        return Err(TrustedListError::UnusableResponse);
    }
    let scheme = sole_child(root, "SchemeInformation", Some(TSL_NAMESPACE))
        .map_err(|_ignored| TrustedListError::UnusableResponse)?;
    let list_type = optional_sole_child_text(scheme, "TSLType")?;
    let territory = optional_sole_child_text(scheme, "SchemeTerritory")?;
    if list_type.as_deref() != Some(EU_GENERIC_TSL_TYPE)
        || territory.is_none()
        || territory != pointer.territory
    {
        return Err(TrustedListError::UnusableResponse);
    }
    Ok(())
}

fn fetch(location: &Uri) -> Result<Vec<u8>, TrustedListError> {
    http::get(location, MAX_LIST_BYTES, user_agent::honest())
        .map_err(|_ignored| TrustedListError::UnusableResponse)
}

fn official_journal_fingerprints() -> Result<HashSet<Vec<u8>>, TrustedListError> {
    let decoded: HashSet<Vec<u8>> = OFFICIAL_JOURNAL_FINGERPRINTS
        .iter()
        .map(|encoded| strict_base64(encoded).ok_or(TrustedListError::Malformed))
        .collect::<Result<_, _>>()?;
    if decoded.len() == OFFICIAL_JOURNAL_FINGERPRINTS.len()
        && decoded.iter().all(|fingerprint| fingerprint.len() == 32)
    {
        Ok(decoded)
    } else {
        Err(TrustedListError::Malformed)
    }
}

fn verify_document(
    encoded: &[u8],
    trust: SignerTrust<'_>,
    validation_time: DateTime,
) -> Result<VerifiedDocument, TrustedListError> {
    let document = parse_xml(encoded)?;
    let parsed = parse_signature(&document)?;
    for reference in &parsed.references {
        let target = document
            .get_node(reference.target)
            .ok_or(TrustedListError::Wrapping)?;
        let canonical = canonicalized(
            &document,
            target,
            reference
                .excludes_signature
                .then_some(parsed.signature_node),
        )?;
        if reference.algorithm.digest(&canonical) != reference.expected_digest {
            return Err(TrustedListError::InvalidDigest);
        }
    }
    let signed_info = document
        .get_node(parsed.signed_info)
        .ok_or(TrustedListError::Wrapping)?;
    let canonical_signed_info = canonicalized(&document, signed_info, None)?;
    let signer = verify_signature(&parsed, &canonical_signed_info, trust)?;
    let (issued_at, next_update, sequence_number) = freshness(&document, validation_time)?;
    validate_signer_profile(&signer, &parsed.binding, issued_at)?;
    Ok(VerifiedDocument {
        next_update,
        version: SignedListVersion {
            sequence_number,
            issued_at,
            document_sha256: Sha256::digest(encoded).into(),
        },
    })
}

fn parse_xml(encoded: &[u8]) -> Result<Document<'_>, TrustedListError> {
    if encoded.is_empty() || encoded.len() > MAX_LIST_BYTES {
        return Err(TrustedListError::Malformed);
    }
    let text = core::str::from_utf8(encoded).map_err(|_ignored| TrustedListError::Malformed)?;
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_XML_NODES,
        entity_resolver: None,
    };
    Document::parse_with_options(text, options).map_err(|_ignored| TrustedListError::Malformed)
}

fn parse_signature(document: &Document<'_>) -> Result<ParsedSignature, TrustedListError> {
    let root = document.root_element();
    if !matches_name(root, "TrustServiceStatusList", Some(TSL_NAMESPACE)) {
        return Err(TrustedListError::Malformed);
    }
    let signatures: Vec<Node<'_, '_>> = root
        .descendants()
        .filter(|node| matches_name(*node, "Signature", Some(DS_NAMESPACE)))
        .collect();
    let [signature] = signatures.as_slice() else {
        return Err(TrustedListError::Wrapping);
    };
    if signature.parent_element() != Some(root) {
        return Err(TrustedListError::Wrapping);
    }
    check_signature_is_bounded(*signature)?;
    let identifiers = identifier_map(root)?;

    let signed_info = sole_child(*signature, "SignedInfo", Some(DS_NAMESPACE))?;
    let signed_children = element_children(signed_info);
    if signed_children.len() != 4
        || !matches_name(
            signed_children[0],
            "CanonicalizationMethod",
            Some(DS_NAMESPACE),
        )
        || !matches_name(signed_children[1], "SignatureMethod", Some(DS_NAMESPACE))
        || !matches_name(signed_children[2], "Reference", Some(DS_NAMESPACE))
        || !matches_name(signed_children[3], "Reference", Some(DS_NAMESPACE))
    {
        return Err(TrustedListError::Malformed);
    }
    let canonicalization = signed_children[0];
    if unqualified_attribute(canonicalization, "Algorithm") != Some(C14N_EXCLUSIVE)
        || !element_children(canonicalization).is_empty()
    {
        return Err(TrustedListError::UnsupportedAlgorithm);
    }
    let algorithm = signature_algorithm(signed_children[1])?;
    let references = vec![
        parse_reference(signed_children[2], root, *signature, &identifiers, document)?,
        parse_reference(signed_children[3], root, *signature, &identifiers, document)?,
    ];
    if references
        .iter()
        .filter(|reference| reference.excludes_signature)
        .count()
        != 1
    {
        return Err(TrustedListError::Malformed);
    }

    let properties = xades_target(*signature, &signed_children[2..], &identifiers, document)?;
    let binding = signer_binding(properties)?;
    let signature_value_node = sole_child(*signature, "SignatureValue", Some(DS_NAMESPACE))?;
    if !element_children(signature_value_node).is_empty() {
        return Err(TrustedListError::Malformed);
    }
    let signature_value = strict_base64_node(signature_value_node)?;
    if signature_value.is_empty() || signature_value.len() > MAX_SIGNATURE_BYTES {
        return Err(TrustedListError::Malformed);
    }
    let key_info = sole_child(*signature, "KeyInfo", Some(DS_NAMESPACE))?;
    let certificate_nodes: Vec<Node<'_, '_>> = key_info
        .descendants()
        .filter(|node| matches_name(*node, "X509Certificate", Some(DS_NAMESPACE)))
        .collect();
    if certificate_nodes.is_empty() {
        return Err(TrustedListError::Malformed);
    }
    let mut certificates = Vec::with_capacity(certificate_nodes.len());
    for node in certificate_nodes {
        if !element_children(node).is_empty() {
            return Err(TrustedListError::Malformed);
        }
        let der = strict_base64_node(node)?;
        if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES || OwnedCert::from_der(&der).is_err()
        {
            return Err(TrustedListError::Malformed);
        }
        certificates.push(der);
    }
    Ok(ParsedSignature {
        algorithm,
        binding,
        certificates,
        references,
        signature_value,
        signature_node: signature.id(),
        signed_info: signed_info.id(),
    })
}

fn check_signature_is_bounded(signature: Node<'_, '_>) -> Result<(), TrustedListError> {
    let children = element_children(signature);
    let permitted = ["SignedInfo", "SignatureValue", "KeyInfo", "Object"];
    if children.iter().any(|child| {
        child.tag_name().namespace() != Some(DS_NAMESPACE)
            || !permitted.contains(&child.tag_name().name())
    }) {
        return Err(TrustedListError::Wrapping);
    }
    for required in ["SignedInfo", "SignatureValue", "KeyInfo"] {
        if children
            .iter()
            .filter(|child| matches_name(**child, required, Some(DS_NAMESPACE)))
            .count()
            != 1
        {
            return Err(TrustedListError::Wrapping);
        }
    }
    let objects: Vec<Node<'_, '_>> = children
        .iter()
        .copied()
        .filter(|child| matches_name(*child, "Object", Some(DS_NAMESPACE)))
        .collect();
    let [object] = objects.as_slice() else {
        return Err(TrustedListError::Wrapping);
    };
    let held = element_children(*object);
    if held.len() != 1 || !matches_name(held[0], "QualifyingProperties", Some(XADES_NAMESPACE)) {
        return Err(TrustedListError::Wrapping);
    }
    Ok(())
}

fn identifier_map(root: Node<'_, '_>) -> Result<HashMap<String, NodeId>, TrustedListError> {
    let mut identifiers = HashMap::new();
    for element in root.descendants().filter(Node::is_element) {
        let values: Vec<&str> = identifier_values(element);
        if values.len() > 1 {
            return Err(TrustedListError::Wrapping);
        }
        let Some(value) = values.first().copied() else {
            continue;
        };
        if value.is_empty()
            || value.chars().any(char::is_whitespace)
            || identifiers.insert(value.to_owned(), element.id()).is_some()
        {
            return Err(TrustedListError::Wrapping);
        }
    }
    Ok(identifiers)
}

fn signature_algorithm(
    method: Node<'_, '_>,
) -> Result<MessageSignatureAlgorithm, TrustedListError> {
    let identifier = unqualified_attribute(method, "Algorithm");
    let children = element_children(method);
    if identifier == Some(RSA_PSS_PARAMETERS) {
        check_sha256_pss_parameters(&children)?;
        return Ok(MessageSignatureAlgorithm::RsaPssSha256);
    }
    if !children.is_empty() {
        return Err(TrustedListError::UnsupportedAlgorithm);
    }
    match identifier {
        Some(RSA_SHA256) => Ok(MessageSignatureAlgorithm::RsaPkcs1Sha256),
        Some(RSA_SHA512) => Ok(MessageSignatureAlgorithm::RsaPkcs1Sha512),
        Some(RSA_PSS_SHA256) => Ok(MessageSignatureAlgorithm::RsaPssSha256),
        Some(ECDSA_SHA256) => Ok(MessageSignatureAlgorithm::EcdsaSha256Raw),
        Some(ECDSA_SHA512) => Ok(MessageSignatureAlgorithm::EcdsaSha512Raw),
        _ => Err(TrustedListError::UnsupportedAlgorithm),
    }
}

fn check_sha256_pss_parameters(children: &[Node<'_, '_>]) -> Result<(), TrustedListError> {
    let [parameters] = children else {
        return Err(TrustedListError::UnsupportedAlgorithm);
    };
    if parameters.tag_name().name() != "RSAPSSParams" {
        return Err(TrustedListError::UnsupportedAlgorithm);
    }
    let values = element_children(*parameters);
    if values.len() != 4 {
        return Err(TrustedListError::UnsupportedAlgorithm);
    }
    let digest: Vec<Node<'_, '_>> = values
        .iter()
        .copied()
        .filter(|node| matches_name(*node, "DigestMethod", Some(DS_NAMESPACE)))
        .collect();
    let salt: Vec<Node<'_, '_>> = values
        .iter()
        .copied()
        .filter(|node| node.tag_name().name() == "SaltLength")
        .collect();
    let trailer: Vec<Node<'_, '_>> = values
        .iter()
        .copied()
        .filter(|node| node.tag_name().name() == "TrailerField")
        .collect();
    let mask: Vec<Node<'_, '_>> = values
        .iter()
        .copied()
        .filter(|node| matches!(node.tag_name().name(), "MaskGenerationFunction" | "MGF"))
        .collect();
    if digest.len() != 1
        || salt.len() != 1
        || trailer.len() != 1
        || mask.len() != 1
        || unqualified_attribute(digest[0], "Algorithm") != Some(DIGEST_SHA256)
        || !element_children(digest[0]).is_empty()
        || text(salt[0]) != "32"
        || !element_children(salt[0]).is_empty()
        || text(trailer[0]) != "1"
        || !element_children(trailer[0]).is_empty()
        || !is_sha256_mask(mask[0])
    {
        return Err(TrustedListError::UnsupportedAlgorithm);
    }
    Ok(())
}

fn is_sha256_mask(mask: Node<'_, '_>) -> bool {
    let algorithm = unqualified_attribute(mask, "Algorithm");
    let children = element_children(mask);
    if algorithm == Some(MGF1_SHA256) {
        return children.is_empty();
    }
    algorithm == Some(MGF1_PARAMETERS)
        && children.len() == 1
        && matches_name(children[0], "DigestMethod", Some(DS_NAMESPACE))
        && unqualified_attribute(children[0], "Algorithm") == Some(DIGEST_SHA256)
        && element_children(children[0]).is_empty()
}

fn parse_reference(
    reference: Node<'_, '_>,
    root: Node<'_, '_>,
    signature: Node<'_, '_>,
    identifiers: &HashMap<String, NodeId>,
    document: &Document<'_>,
) -> Result<Reference, TrustedListError> {
    let children = element_children(reference);
    if children.len() != 3
        || !matches_name(children[0], "Transforms", Some(DS_NAMESPACE))
        || !matches_name(children[1], "DigestMethod", Some(DS_NAMESPACE))
        || !matches_name(children[2], "DigestValue", Some(DS_NAMESPACE))
    {
        return Err(TrustedListError::Malformed);
    }
    let transforms: Vec<&str> = element_children(children[0])
        .into_iter()
        .map(|transform| {
            if matches_name(transform, "Transform", Some(DS_NAMESPACE))
                && element_children(transform).is_empty()
            {
                unqualified_attribute(transform, "Algorithm")
                    .ok_or(TrustedListError::UnsupportedAlgorithm)
            } else {
                Err(TrustedListError::UnsupportedAlgorithm)
            }
        })
        .collect::<Result<_, _>>()?;
    let uri = unqualified_attribute(reference, "URI").ok_or(TrustedListError::Malformed)?;
    let reference_type = unqualified_attribute(reference, "Type");
    let (target, excludes_signature) = if reference_type == Some(SIGNED_PROPERTIES_TYPE) {
        if transforms != [C14N_EXCLUSIVE] {
            return Err(TrustedListError::UnsupportedAlgorithm);
        }
        let target = resolve(uri, identifiers, document).ok_or(TrustedListError::Wrapping)?;
        if !matches_name(target, "SignedProperties", Some(XADES_NAMESPACE))
            || !is_descendant(target, signature)
        {
            return Err(TrustedListError::Wrapping);
        }
        (target, false)
    } else {
        if reference_type.is_some() || transforms != [ENVELOPED_TRANSFORM, C14N_EXCLUSIVE] {
            return Err(TrustedListError::UnsupportedAlgorithm);
        }
        let target = if uri.is_empty() {
            root
        } else {
            resolve(uri, identifiers, document).ok_or(TrustedListError::Wrapping)?
        };
        if target != root {
            return Err(TrustedListError::Wrapping);
        }
        (target, true)
    };
    let algorithm = digest_algorithm(children[1])?;
    if !element_children(children[2]).is_empty() {
        return Err(TrustedListError::Malformed);
    }
    let expected_digest = strict_base64_node(children[2])?;
    if expected_digest.len() != algorithm.output_bytes() {
        return Err(TrustedListError::Malformed);
    }
    Ok(Reference {
        algorithm,
        expected_digest,
        excludes_signature,
        target: target.id(),
    })
}

fn digest_algorithm(method: Node<'_, '_>) -> Result<DigestAlgorithm, TrustedListError> {
    if !element_children(method).is_empty() {
        return Err(TrustedListError::UnsupportedAlgorithm);
    }
    match unqualified_attribute(method, "Algorithm") {
        Some(DIGEST_SHA256) => Ok(DigestAlgorithm::Sha256),
        Some(DIGEST_SHA512) => Ok(DigestAlgorithm::Sha512),
        _ => Err(TrustedListError::UnsupportedAlgorithm),
    }
}

fn xades_target<'a, 'input>(
    signature: Node<'a, 'input>,
    reference_nodes: &[Node<'a, 'input>],
    identifiers: &HashMap<String, NodeId>,
    document: &'a Document<'input>,
) -> Result<Node<'a, 'input>, TrustedListError> {
    let signature_ids = identifier_values(signature);
    let [signature_id] = signature_ids.as_slice() else {
        return Err(TrustedListError::Wrapping);
    };
    let property_references: Vec<Node<'_, '_>> = reference_nodes
        .iter()
        .copied()
        .filter(|reference| {
            unqualified_attribute(*reference, "Type") == Some(SIGNED_PROPERTIES_TYPE)
        })
        .collect();
    let [property_reference] = property_references.as_slice() else {
        return Err(TrustedListError::Wrapping);
    };
    let uri =
        unqualified_attribute(*property_reference, "URI").ok_or(TrustedListError::Wrapping)?;
    let properties = resolve(uri, identifiers, document).ok_or(TrustedListError::Wrapping)?;
    let qualifying = properties
        .ancestors()
        .take_while(|ancestor| *ancestor != signature)
        .find(|ancestor| matches_name(*ancestor, "QualifyingProperties", Some(XADES_NAMESPACE)))
        .ok_or(TrustedListError::Wrapping)?;
    let expected_target = format!("#{signature_id}");
    if unqualified_attribute(qualifying, "Target") != Some(expected_target.as_str()) {
        return Err(TrustedListError::Wrapping);
    }
    Ok(properties)
}

fn signer_binding(properties: Node<'_, '_>) -> Result<SignerBinding, TrustedListError> {
    let signed_signature_properties = sole_child(
        properties,
        "SignedSignatureProperties",
        Some(XADES_NAMESPACE),
    )?;
    let signing_time_node = sole_child(
        signed_signature_properties,
        "SigningTime",
        Some(XADES_NAMESPACE),
    )?;
    if !element_children(signing_time_node).is_empty() {
        return Err(TrustedListError::Malformed);
    }
    let signing_time = parse_xml_datetime(&text(signing_time_node))?;
    let signing_certificates = sole_child(
        signed_signature_properties,
        "SigningCertificateV2",
        Some(XADES_NAMESPACE),
    )?;
    let certificate = sole_child(signing_certificates, "Cert", Some(XADES_NAMESPACE))?;
    if element_children(signing_certificates).len() != 1 {
        return Err(TrustedListError::Malformed);
    }
    let digest = sole_child(certificate, "CertDigest", Some(XADES_NAMESPACE))?;
    let certificate_children = element_children(certificate);
    let issuers: Vec<Node<'_, '_>> = certificate_children
        .iter()
        .copied()
        .filter(|node| matches_name(*node, "IssuerSerialV2", Some(XADES_NAMESPACE)))
        .collect();
    if issuers.len() > 1
        || certificate_children.len() != 1 + issuers.len()
        || !certificate_children.contains(&digest)
    {
        return Err(TrustedListError::Malformed);
    }
    let digest_children = element_children(digest);
    if digest_children.len() != 2
        || !matches_name(digest_children[0], "DigestMethod", Some(DS_NAMESPACE))
        || !matches_name(digest_children[1], "DigestValue", Some(DS_NAMESPACE))
    {
        return Err(TrustedListError::Malformed);
    }
    let algorithm = digest_algorithm(digest_children[0])?;
    if !element_children(digest_children[1]).is_empty() {
        return Err(TrustedListError::Malformed);
    }
    let certificate_digest = strict_base64_node(digest_children[1])?;
    if certificate_digest.len() != algorithm.output_bytes() {
        return Err(TrustedListError::Malformed);
    }
    Ok(SignerBinding {
        algorithm,
        certificate_digest,
        signing_time,
    })
}

fn verify_signature(
    parsed: &ParsedSignature,
    canonical_signed_info: &[u8],
    trust: SignerTrust<'_>,
) -> Result<Vec<u8>, TrustedListError> {
    let candidates: HashSet<Vec<u8>> = parsed
        .certificates
        .iter()
        .filter(|certificate| is_trusted(certificate, &trust))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return Err(TrustedListError::UntrustedSigner);
    }
    let verified: Vec<Vec<u8>> = candidates
        .into_iter()
        .filter(|encoded| {
            OwnedCert::from_der(encoded).is_ok_and(|certificate| {
                certificate
                    .view()
                    .spki
                    .verify_message_signature(
                        parsed.algorithm,
                        canonical_signed_info,
                        &parsed.signature_value,
                    )
                    .is_ok()
            })
        })
        .collect();
    let [signer] = verified.as_slice() else {
        return Err(TrustedListError::InvalidSignature);
    };
    Ok(signer.clone())
}

fn is_trusted(certificate: &[u8], trust: &SignerTrust<'_>) -> bool {
    match trust {
        SignerTrust::Certificates(allowed) => allowed.contains(certificate),
        SignerTrust::Sha256Fingerprints(allowed) => {
            let digest: [u8; 32] = Sha256::digest(certificate).into();
            allowed.contains(digest.as_slice())
        }
    }
}

fn validate_signer_profile(
    encoded: &[u8],
    binding: &SignerBinding,
    issued_at: DateTime,
) -> Result<(), TrustedListError> {
    if binding.algorithm.digest(encoded) != binding.certificate_digest {
        return Err(TrustedListError::InvalidSignerProfile);
    }
    let certificate =
        OwnedCert::from_der(encoded).map_err(|_ignored| TrustedListError::InvalidSignerProfile)?;
    let certificate = certificate.view();
    if issued_at < certificate.not_before
        || issued_at > certificate.not_after
        || binding.signing_time < certificate.not_before
        || binding.signing_time > certificate.not_after
    {
        return Err(TrustedListError::InvalidSignerProfile);
    }
    let extensions = certificate.extensions.unwrap_or_default();
    if extract_basic_constraints(extensions).ca {
        return Err(TrustedListError::InvalidSignerProfile);
    }
    if let Some(usage) = extract_key_usage(extensions)
        && !usage.digital_signature
        && !usage.non_repudiation
    {
        return Err(TrustedListError::InvalidSignerProfile);
    }
    Ok(())
}

fn freshness(
    document: &Document<'_>,
    validation_time: DateTime,
) -> Result<(DateTime, DateTime, u64), TrustedListError> {
    let root = document.root_element();
    let scheme = sole_child(root, "SchemeInformation", Some(TSL_NAMESPACE))?;
    let sequence_node = sole_child(scheme, "TSLSequenceNumber", Some(TSL_NAMESPACE))?;
    let issue_node = sole_child(scheme, "ListIssueDateTime", Some(TSL_NAMESPACE))?;
    let next_node = sole_child(scheme, "NextUpdate", Some(TSL_NAMESPACE))?;
    let date_node = sole_child(next_node, "dateTime", Some(TSL_NAMESPACE))?;
    if !element_children(sequence_node).is_empty()
        || !element_children(issue_node).is_empty()
        || !element_children(date_node).is_empty()
    {
        return Err(TrustedListError::Malformed);
    }
    let sequence_text = text(sequence_node);
    if sequence_text.is_empty() || !sequence_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TrustedListError::Malformed);
    }
    let sequence_number = sequence_text
        .parse::<u64>()
        .map_err(|_ignored| TrustedListError::Malformed)?;
    let issued_at = parse_xml_datetime(&text(issue_node))?;
    let next_update = parse_xml_datetime(&text(date_node))?;
    let maximum = maximum_next_update(issued_at)?;
    if issued_at >= next_update
        || next_update > maximum
        || validation_time < issued_at
        || validation_time >= next_update
    {
        return Err(TrustedListError::Stale);
    }
    Ok((issued_at, next_update, sequence_number))
}

fn maximum_next_update(issued_at: DateTime) -> Result<DateTime, TrustedListError> {
    let zero_based_month = u16::from(issued_at.month())
        .checked_sub(1)
        .ok_or(TrustedListError::Stale)?;
    let absolute_month = issued_at
        .year()
        .checked_mul(12)
        .and_then(|months| months.checked_add(zero_based_month))
        .and_then(|months| months.checked_add(6))
        .ok_or(TrustedListError::Stale)?;
    let year = absolute_month
        .checked_div(12)
        .ok_or(TrustedListError::Stale)?;
    let month = absolute_month
        .checked_rem(12)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(TrustedListError::Stale)?;
    let day = issued_at.day().min(days_in_month(year, month));
    let six_months = DateTime::new(
        year,
        month,
        day,
        issued_at.hour(),
        issued_at.minutes(),
        issued_at.seconds(),
    )
    .map_err(|_ignored| TrustedListError::Stale)?;
    let with_skew = six_months
        .unix_duration()
        .checked_add(FRESHNESS_SKEW)
        .ok_or(TrustedListError::Stale)?;
    DateTime::from_unix_duration(with_skew).map_err(|_ignored| TrustedListError::Stale)
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn parse_xml_datetime(encoded: &str) -> Result<DateTime, TrustedListError> {
    let bytes = encoded.as_bytes();
    if !bytes.is_ascii() || bytes.len() < 20 {
        return Err(TrustedListError::Malformed);
    }
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return Err(TrustedListError::Malformed);
    }
    let year = parse_digits_u16(bytes.get(0..4).ok_or(TrustedListError::Malformed)?)?;
    let month = parse_digits_u8(bytes.get(5..7).ok_or(TrustedListError::Malformed)?)?;
    let day = parse_digits_u8(bytes.get(8..10).ok_or(TrustedListError::Malformed)?)?;
    let hour = parse_digits_u8(bytes.get(11..13).ok_or(TrustedListError::Malformed)?)?;
    let minute = parse_digits_u8(bytes.get(14..16).ok_or(TrustedListError::Malformed)?)?;
    let second = parse_digits_u8(bytes.get(17..19).ok_or(TrustedListError::Malformed)?)?;
    let mut suffix = bytes.get(19..).ok_or(TrustedListError::Malformed)?;
    if suffix.first() == Some(&b'.') {
        let count = suffix
            .get(1..)
            .unwrap_or_default()
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if count == 0 {
            return Err(TrustedListError::Malformed);
        }
        suffix = suffix
            .get(count.checked_add(1).ok_or(TrustedListError::Malformed)?..)
            .ok_or(TrustedListError::Malformed)?;
    }
    let offset_seconds: i64 = match suffix {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), oh1, oh2, b':', om1, om2] => {
            let hours = parse_digits_u8(&[*oh1, *oh2])?;
            let minutes = parse_digits_u8(&[*om1, *om2])?;
            if hours > 14 || minutes > 59 {
                return Err(TrustedListError::Malformed);
            }
            let seconds = i64::from(hours)
                .checked_mul(3_600)
                .and_then(|value| value.checked_add(i64::from(minutes) * 60))
                .ok_or(TrustedListError::Malformed)?;
            if *sign == b'-' { -seconds } else { seconds }
        }
        _ => return Err(TrustedListError::Malformed),
    };
    let local = DateTime::new(year, month, day, hour, minute, second)
        .map_err(|_ignored| TrustedListError::Malformed)?;
    let local_seconds = i64::try_from(local.unix_duration().as_secs())
        .map_err(|_ignored| TrustedListError::Malformed)?;
    let utc_seconds = local_seconds
        .checked_sub(offset_seconds)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or(TrustedListError::Malformed)?;
    DateTime::from_unix_duration(Duration::from_secs(utc_seconds))
        .map_err(|_ignored| TrustedListError::Malformed)
}

fn parse_digits_u8(bytes: &[u8]) -> Result<u8, TrustedListError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(TrustedListError::Malformed);
    }
    bytes.iter().try_fold(0_u8, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(byte.saturating_sub(b'0')))
            .ok_or(TrustedListError::Malformed)
    })
}

fn parse_digits_u16(bytes: &[u8]) -> Result<u16, TrustedListError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(TrustedListError::Malformed);
    }
    bytes.iter().try_fold(0_u16, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(byte.saturating_sub(b'0'))))
            .ok_or(TrustedListError::Malformed)
    })
}

fn canonicalized(
    document: &Document<'_>,
    target: Node<'_, '_>,
    excluded_signature: Option<NodeId>,
) -> Result<Vec<u8>, TrustedListError> {
    let target_id = target.id();
    let visible = |node: Node<'_, '_>| {
        let inside_target =
            node.id() == target_id || node.ancestors().any(|ancestor| ancestor.id() == target_id);
        let inside_excluded = excluded_signature.is_some_and(|signature| {
            node.id() == signature || node.ancestors().any(|ancestor| ancestor.id() == signature)
        });
        inside_target && !inside_excluded
    };
    canonical_output_preflight(document, &visible)?;
    let algorithm =
        C14nAlgorithm::from_uri(C14N_EXCLUSIVE).ok_or(TrustedListError::UnsupportedAlgorithm)?;
    let mut output = Vec::new();
    canonicalize(document, Some(&visible), &algorithm, &mut output)
        .map_err(|_ignored| TrustedListError::Malformed)?;
    if output.len() > MAX_CANONICAL_BYTES {
        Err(TrustedListError::Malformed)
    } else {
        Ok(output)
    }
}

fn canonical_output_preflight(
    document: &Document<'_>,
    visible: &dyn Fn(Node<'_, '_>) -> bool,
) -> Result<(), TrustedListError> {
    // Five times the source length covers canonical attribute escaping and
    // empty-tag expansion. Each visibly used namespace is then charged again
    // at every visible element where exclusive C14N could repeat it.
    let mut estimate = document
        .input_text()
        .len()
        .checked_mul(5)
        .ok_or(TrustedListError::Malformed)?;
    for element in document.descendants().filter(Node::is_element) {
        if !visible(element) {
            continue;
        }
        estimate = estimate
            .checked_add(element.tag_name().name().len())
            .and_then(|value| value.checked_add(5))
            .ok_or(TrustedListError::Malformed)?;
        if let Some(namespace) = element.tag_name().namespace() {
            estimate = add_namespace_estimate(estimate, element, namespace)?;
        }
        for attribute in element.attributes() {
            if let Some(namespace) = attribute.namespace() {
                estimate = add_namespace_estimate(estimate, element, namespace)?;
            }
        }
        if estimate > MAX_CANONICAL_BYTES {
            return Err(TrustedListError::Malformed);
        }
    }
    Ok(())
}

fn add_namespace_estimate(
    estimate: usize,
    element: Node<'_, '_>,
    namespace: &str,
) -> Result<usize, TrustedListError> {
    let prefix_bytes = element.lookup_prefix(namespace).map_or(0, str::len);
    estimate
        .checked_add(prefix_bytes)
        .and_then(|value| value.checked_add(namespace.len()))
        .and_then(|value| value.checked_add(16))
        .ok_or(TrustedListError::Malformed)
}

fn trusted_list_pointers(encoded: &[u8]) -> Result<Vec<TrustedListPointer>, TrustedListError> {
    let document = parse_xml(encoded)?;
    let root = document.root_element();
    if !matches_name(root, "TrustServiceStatusList", Some(TSL_NAMESPACE)) {
        return Err(TrustedListError::UnusableResponse);
    }
    let scheme = sole_child(root, "SchemeInformation", Some(TSL_NAMESPACE))?;
    let pointers_container = sole_child(scheme, "PointersToOtherTSL", Some(TSL_NAMESPACE))?;
    let nodes: Vec<Node<'_, '_>> = element_children(pointers_container)
        .into_iter()
        .filter(|node| matches_name(*node, "OtherTSLPointer", Some(TSL_NAMESPACE)))
        .collect();
    let mut ordered = Vec::new();
    let mut seen: HashMap<String, TrustedListPointer> = HashMap::new();
    for pointer in nodes {
        let territory = pointer_metadata_value(pointer, "SchemeTerritory", Some(TSL_NAMESPACE))?;
        if territory.as_deref() == Some("UK") {
            continue;
        }
        let mime_type =
            pointer_metadata_value(pointer, "MimeType", Some(TSL_ADDITIONAL_TYPES_NAMESPACE))?
                .map(|value| value.to_ascii_lowercase());
        if mime_type.as_deref() == Some(PDF_MIME_TYPE) {
            continue;
        }
        if mime_type.as_deref() != Some(TRUSTED_LIST_MIME_TYPE) {
            return Err(TrustedListError::UnusableResponse);
        }
        let tsl_type = pointer_metadata_value(pointer, "TSLType", Some(TSL_NAMESPACE))?;
        if tsl_type.as_deref() != Some(EU_GENERIC_TSL_TYPE) {
            continue;
        }
        let locations = children_named(pointer, "TSLLocation", Some(TSL_NAMESPACE));
        let [location_node] = locations.as_slice() else {
            return Err(TrustedListError::UnusableResponse);
        };
        let location_text = text(*location_node);
        if location_text.is_empty() || location_text == EU_LIST_OF_LISTS {
            continue;
        }
        let location = Uri::parse(location_text.clone())
            .map_err(|_ignored| TrustedListError::UnusableResponse)?;
        let signing_certificates = pointer_signing_certificates(pointer)?;
        if signing_certificates.is_empty() {
            return Err(TrustedListError::UnusableResponse);
        }
        let candidate = TrustedListPointer {
            location,
            signing_certificates,
            territory,
        };
        if let Some(previous) = seen.get(&location_text) {
            if previous != &candidate {
                return Err(TrustedListError::UnusableResponse);
            }
            continue;
        }
        seen.insert(location_text, candidate.clone());
        ordered.push(candidate);
    }
    Ok(ordered)
}

fn pointer_metadata_value(
    pointer: Node<'_, '_>,
    field: &str,
    namespace: Option<&str>,
) -> Result<Option<String>, TrustedListError> {
    let mut found = Vec::new();
    for additional in children_named(pointer, "AdditionalInformation", Some(TSL_NAMESPACE)) {
        for other in children_named(additional, "OtherInformation", Some(TSL_NAMESPACE)) {
            for value in children_named(other, field, namespace) {
                found.push(text(value));
            }
        }
    }
    if found.len() > 1 {
        return Err(TrustedListError::UnusableResponse);
    }
    Ok(found.pop())
}

fn pointer_signing_certificates(
    pointer: Node<'_, '_>,
) -> Result<HashSet<Vec<u8>>, TrustedListError> {
    let mut nodes = Vec::new();
    for identities in children_named(pointer, "ServiceDigitalIdentities", Some(TSL_NAMESPACE)) {
        for identity in children_named(identities, "ServiceDigitalIdentity", Some(TSL_NAMESPACE)) {
            for digital_id in children_named(identity, "DigitalId", Some(TSL_NAMESPACE)) {
                nodes.extend(children_named(
                    digital_id,
                    "X509Certificate",
                    Some(TSL_NAMESPACE),
                ));
            }
        }
    }
    let mut certificates = HashSet::new();
    for node in nodes {
        let der =
            strict_base64_node(node).map_err(|_ignored| TrustedListError::UnusableResponse)?;
        if der.len() > MAX_CERTIFICATE_BYTES || OwnedCert::from_der(&der).is_err() {
            return Err(TrustedListError::UnusableResponse);
        }
        certificates.insert(der);
    }
    Ok(certificates)
}

fn qualified_timestamp_identities_in(
    encoded: &[u8],
    validation_time: DateTime,
) -> Result<Vec<TrustedTimestampIdentity>, TrustedListError> {
    let document = parse_xml(encoded)?;
    let root = document.root_element();
    if !matches_name(root, "TrustServiceStatusList", Some(TSL_NAMESPACE)) {
        return Err(TrustedListError::UnusableResponse);
    }
    let provider_lists = children_named(root, "TrustServiceProviderList", Some(TSL_NAMESPACE));
    if provider_lists.len() > 1 {
        return Err(TrustedListError::UnusableResponse);
    }
    let mut services = Vec::new();
    for provider_list in provider_lists {
        for provider in children_named(provider_list, "TrustServiceProvider", Some(TSL_NAMESPACE)) {
            for tsp_services in children_named(provider, "TSPServices", Some(TSL_NAMESPACE)) {
                services.extend(children_named(
                    tsp_services,
                    "TSPService",
                    Some(TSL_NAMESPACE),
                ));
            }
        }
    }
    let mut found = Vec::new();
    for service in services {
        let information = sole_child(service, "ServiceInformation", Some(TSL_NAMESPACE))
            .map_err(|_ignored| TrustedListError::UnusableResponse)?;
        let service_type = optional_sole_child_text(information, "ServiceTypeIdentifier")?;
        let service_status = optional_sole_child_text(information, "ServiceStatus")?;
        if service_type.as_deref() != Some(QUALIFIED_TIMESTAMP_TYPE)
            || service_status.as_deref() != Some(GRANTED_STATUS)
        {
            continue;
        }
        let starting_time = optional_sole_child_text(information, "StatusStartingTime")?
            .ok_or(TrustedListError::UnusableResponse)
            .and_then(|value| {
                parse_xml_datetime(&value).map_err(|_ignored| TrustedListError::UnusableResponse)
            })?;
        if starting_time > validation_time {
            return Err(TrustedListError::UnusableResponse);
        }
        let identities = children_named(information, "ServiceDigitalIdentity", Some(TSL_NAMESPACE));
        let mut service_identities = Vec::new();
        for identity in identities {
            for digital_id in children_named(identity, "DigitalId", Some(TSL_NAMESPACE)) {
                for node in children_named(digital_id, "X509Certificate", Some(TSL_NAMESPACE)) {
                    let der = strict_base64_node(node)
                        .map_err(|_ignored| TrustedListError::UnusableResponse)?;
                    if der.len() > MAX_CERTIFICATE_BYTES || OwnedCert::from_der(&der).is_err() {
                        return Err(TrustedListError::UnusableResponse);
                    }
                    service_identities.push(TrustedTimestampIdentity {
                        certificate_der: der,
                        granted_from: starting_time,
                    });
                }
            }
        }
        if service_identities.is_empty() {
            return Err(TrustedListError::UnusableResponse);
        }
        found.extend(service_identities);
    }
    Ok(found)
}

fn optional_sole_child_text(
    parent: Node<'_, '_>,
    name: &str,
) -> Result<Option<String>, TrustedListError> {
    let children = children_named(parent, name, Some(TSL_NAMESPACE));
    if children.len() > 1 {
        return Err(TrustedListError::UnusableResponse);
    }
    Ok(children.first().copied().map(text))
}

fn resolve<'a, 'input>(
    uri: &str,
    identifiers: &HashMap<String, NodeId>,
    document: &'a Document<'input>,
) -> Option<Node<'a, 'input>> {
    if !uri.starts_with('#') || uri.len() <= 1 || uri.contains('%') || uri.contains('(') {
        return None;
    }
    identifiers
        .get(uri.get(1..)?)
        .and_then(|identifier| document.get_node(*identifier))
}

fn is_descendant(node: Node<'_, '_>, ancestor: Node<'_, '_>) -> bool {
    node.ancestors()
        .skip(1)
        .any(|candidate| candidate == ancestor)
}

fn element_children<'a, 'input>(node: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    node.children().filter(Node::is_element).collect()
}

fn children_named<'a, 'input>(
    node: Node<'a, 'input>,
    name: &str,
    namespace: Option<&str>,
) -> Vec<Node<'a, 'input>> {
    node.children()
        .filter(Node::is_element)
        .filter(|child| matches_name(*child, name, namespace))
        .collect()
}

fn sole_child<'a, 'input>(
    node: Node<'a, 'input>,
    name: &str,
    namespace: Option<&str>,
) -> Result<Node<'a, 'input>, TrustedListError> {
    let children = children_named(node, name, namespace);
    let [child] = children.as_slice() else {
        return Err(TrustedListError::Malformed);
    };
    Ok(*child)
}

fn matches_name(node: Node<'_, '_>, name: &str, namespace: Option<&str>) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && namespace.is_none_or(|expected| node.tag_name().namespace() == Some(expected))
}

fn unqualified_attribute<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attributes()
        .find(|attribute| attribute.namespace().is_none() && attribute.name() == name)
        .map(|attribute| attribute.value())
}

fn identifier_values<'a>(node: Node<'a, '_>) -> Vec<&'a str> {
    node.attributes()
        .filter_map(|attribute| {
            let name = attribute.name();
            let namespace = attribute.namespace();
            ((namespace.is_none() && matches!(name, "Id" | "ID" | "id"))
                || (namespace == Some(XML_NAMESPACE) && name == "id"))
                .then_some(attribute.value())
        })
        .collect()
}

fn text(node: Node<'_, '_>) -> String {
    let mut value = String::new();
    for child in node.children() {
        if child.is_text() {
            value.push_str(child.text().unwrap_or_default());
        }
    }
    value.trim().to_owned()
}

fn strict_base64_node(node: Node<'_, '_>) -> Result<Vec<u8>, TrustedListError> {
    let value = text(node);
    strict_base64(&value).ok_or(TrustedListError::Malformed)
}

fn strict_base64(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.is_ascii() {
        return None;
    }
    let compact: String = encoded
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\n' | '\r'))
        .collect();
    crate::text::base64_decode(&compact)
}

fn now_datetime() -> Result<DateTime, TrustedListError> {
    let elapsed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_ignored| TrustedListError::Stale)?;
    DateTime::from_unix_duration(elapsed).map_err(|_ignored| TrustedListError::Stale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};

    const FIXTURE_CERTIFICATE: &[u8] =
        include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der");

    fn encoded_certificate() -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in FIXTURE_CERTIFICATE.chunks(3) {
            let first = u32::from(*chunk.first().unwrap_or(&0));
            let second = u32::from(*chunk.get(1).unwrap_or(&0));
            let third = u32::from(*chunk.get(2).unwrap_or(&0));
            let value = (first << 16) | (second << 8) | third;
            let sextet = |shift: u32| {
                usize::try_from((value >> shift) & 63)
                    .ok()
                    .and_then(|index| ALPHABET.get(index))
                    .copied()
                    .map_or('A', char::from)
            };
            output.push(sextet(18));
            output.push(sextet(12));
            output.push(if chunk.len() > 1 { sextet(6) } else { '=' });
            output.push(if chunk.len() > 2 { sextet(0) } else { '=' });
        }
        output
    }

    fn signature_xml(root_id: &str, property_id: &str, transform: &str, method: &str) -> String {
        let certificate = encoded_certificate();
        let sha256_zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        format!(
            r##"<ds:Signature xmlns:ds="{DS_NAMESPACE}" xmlns:xades="{XADES_NAMESPACE}" Id="signature">
<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{C14N_EXCLUSIVE}"/>
<ds:SignatureMethod Algorithm="{method}"/>
<ds:Reference URI="#{root_id}"><ds:Transforms><ds:Transform Algorithm="{transform}"/><ds:Transform Algorithm="{C14N_EXCLUSIVE}"/></ds:Transforms><ds:DigestMethod Algorithm="{DIGEST_SHA256}"/><ds:DigestValue>{sha256_zero}</ds:DigestValue></ds:Reference>
<ds:Reference Type="{SIGNED_PROPERTIES_TYPE}" URI="#{property_id}"><ds:Transforms><ds:Transform Algorithm="{C14N_EXCLUSIVE}"/></ds:Transforms><ds:DigestMethod Algorithm="{DIGEST_SHA256}"/><ds:DigestValue>{sha256_zero}</ds:DigestValue></ds:Reference></ds:SignedInfo>
<ds:SignatureValue>AQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
<ds:Object><xades:QualifyingProperties Target="#signature"><xades:SignedProperties Id="{property_id}"><xades:SignedSignatureProperties><xades:SigningTime>2026-08-04T00:00:00Z</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="{DIGEST_SHA256}"/><ds:DigestValue>{sha256_zero}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>"##
        )
    }

    fn list_with(signature: &str, scheme_extra: &str) -> Vec<u8> {
        format!(
            r#"<TrustServiceStatusList xmlns="{TSL_NAMESPACE}" Id="list"><SchemeInformation><ListIssueDateTime>2026-08-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-09-01T00:00:00Z</dateTime></NextUpdate>{scheme_extra}</SchemeInformation>{signature}</TrustServiceStatusList>"#
        )
        .into_bytes()
    }

    fn parse_fixture() -> Result<ParsedSignature, TrustedListError> {
        let signature = signature_xml("list", "properties", ENVELOPED_TRANSFORM, RSA_SHA256);
        let encoded = list_with(&signature, "");
        let document = parse_xml(&encoded)?;
        parse_signature(&document)
    }

    #[test]
    fn constrained_signature_shape_parses_before_crypto() -> TestResult {
        let parsed = parse_fixture()?;
        check(&parsed.references.len(), &2_usize, "reference count")?;
        check(
            &parsed.algorithm,
            &MessageSignatureAlgorithm::RsaPkcs1Sha256,
            "signature algorithm",
        )
    }

    #[test]
    fn duplicate_id_is_rejected_before_digest_processing() -> TestResult {
        let signature = signature_xml("list", "properties", ENVELOPED_TRANSFORM, RSA_SHA256);
        let encoded = list_with(
            &signature,
            "<TSLSequenceNumber Id=\"properties\">1</TSLSequenceNumber>",
        );
        let document = parse_xml(&encoded)?;
        check(
            &parse_signature(&document).err(),
            &Some(TrustedListError::Wrapping),
            "duplicate ID",
        )
    }

    #[test]
    fn external_and_xpointer_references_are_rejected() -> TestResult {
        for target in [
            "https://attacker.test/list",
            "#xpointer(/)",
            "#pro%70erties",
        ] {
            let signature = signature_xml("list", "properties", ENVELOPED_TRANSFORM, RSA_SHA256)
                .replacen("URI=\"#properties\"", &format!("URI=\"{target}\""), 1);
            let encoded = list_with(&signature, "");
            let document = parse_xml(&encoded)?;
            check(
                &parse_signature(&document).err(),
                &Some(TrustedListError::Wrapping),
                "external reference",
            )?;
        }
        Ok(())
    }

    #[test]
    fn transform_and_signature_algorithm_confusion_fail_closed() -> TestResult {
        let bad_transform = signature_xml(
            "list",
            "properties",
            "http://www.w3.org/2000/09/xmldsig#base64",
            RSA_SHA256,
        );
        let encoded = list_with(&bad_transform, "");
        let document = parse_xml(&encoded)?;
        check(
            &parse_signature(&document).err(),
            &Some(TrustedListError::UnsupportedAlgorithm),
            "transform confusion",
        )?;

        let bad_method = signature_xml(
            "list",
            "properties",
            ENVELOPED_TRANSFORM,
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        );
        let encoded = list_with(&bad_method, "");
        let document = parse_xml(&encoded)?;
        check(
            &parse_signature(&document).err(),
            &Some(TrustedListError::UnsupportedAlgorithm),
            "signature algorithm confusion",
        )
    }

    #[test]
    fn signature_wrapping_payload_is_rejected() -> TestResult {
        let mut signature = signature_xml("list", "properties", ENVELOPED_TRANSFORM, RSA_SHA256);
        signature = signature.replace(
            "</ds:Signature>",
            "<TSPService><ServiceInformation/></TSPService></ds:Signature>",
        );
        let encoded = list_with(&signature, "");
        let document = parse_xml(&encoded)?;
        check(
            &parse_signature(&document).err(),
            &Some(TrustedListError::Wrapping),
            "signature wrapping payload",
        )
    }

    #[test]
    fn readers_ignore_services_and_pointers_inside_signature() -> TestResult {
        let certificate = encoded_certificate();
        let hidden = format!(
            r#"<TrustServiceStatusList xmlns="{TSL_NAMESPACE}" xmlns:ds="{DS_NAMESPACE}"><SchemeInformation><PointersToOtherTSL/></SchemeInformation><ds:Signature><ds:Object><OtherTSLPointer><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities><TSLLocation>https://attacker.test/list.xml</TSLLocation></OtherTSLPointer><TSPService><ServiceInformation><ServiceTypeIdentifier>{QUALIFIED_TIMESTAMP_TYPE}</ServiceTypeIdentifier><ServiceStatus>{GRANTED_STATUS}</ServiceStatus><StatusStartingTime>2026-08-01T00:00:00Z</StatusStartingTime><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceInformation></TSPService></ds:Object></ds:Signature></TrustServiceStatusList>"#
        );
        check_true(
            trusted_list_pointers(hidden.as_bytes())?.is_empty(),
            "hidden pointer ignored",
        )?;
        let now = parse_xml_datetime("2026-08-04T00:00:00Z")?;
        check_true(
            qualified_timestamp_identities_in(hidden.as_bytes(), now)?.is_empty(),
            "hidden service ignored",
        )
    }

    #[test]
    fn pointer_conflicts_are_rejected() -> TestResult {
        let certificate = encoded_certificate();
        let pointer = |territory: &str| {
            format!(
                r#"<OtherTSLPointer xmlns:at="{TSL_ADDITIONAL_TYPES_NAMESPACE}"><ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities><TSLLocation>https://example.test/list.xml</TSLLocation><AdditionalInformation><OtherInformation><TSLType>{EU_GENERIC_TSL_TYPE}</TSLType></OtherInformation><OtherInformation><SchemeTerritory>{territory}</SchemeTerritory></OtherInformation><OtherInformation><at:MimeType>{TRUSTED_LIST_MIME_TYPE}</at:MimeType></OtherInformation></AdditionalInformation></OtherTSLPointer>"#
            )
        };
        let scheme = format!(
            "<PointersToOtherTSL>{}{}</PointersToOtherTSL>",
            pointer("FI"),
            pointer("SE")
        );
        let encoded = list_with("", &scheme);
        check(
            &trusted_list_pointers(&encoded).err(),
            &Some(TrustedListError::UnusableResponse),
            "conflicting pointers",
        )
    }

    #[test]
    fn qualified_service_extraction_records_signed_grant_start() -> TestResult {
        let certificate = encoded_certificate();
        let providers = format!(
            r"<TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation><ServiceTypeIdentifier>{QUALIFIED_TIMESTAMP_TYPE}</ServiceTypeIdentifier><ServiceStatus>{GRANTED_STATUS}</ServiceStatus><StatusStartingTime>2026-08-01T00:00:00Z</StatusStartingTime><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceInformation><ServiceHistory><ServiceHistoryInstance><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus></ServiceHistoryInstance></ServiceHistory></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>"
        );
        let encoded = format!(
            r#"<TrustServiceStatusList xmlns="{TSL_NAMESPACE}"><SchemeInformation/>{providers}</TrustServiceStatusList>"#
        );
        let now = parse_xml_datetime("2026-08-04T00:00:00Z")?;
        let found = qualified_timestamp_identities_in(encoded.as_bytes(), now)?;
        check(&found.len(), &1_usize, "qualified identity count")?;
        let identity = found.first().ok_or("missing identity")?;
        check(
            &identity.certificate_der,
            &FIXTURE_CERTIFICATE.to_vec(),
            "qualified certificate",
        )?;
        check(
            &identity.granted_from,
            &parse_xml_datetime("2026-08-01T00:00:00Z")?,
            "grant start",
        )
    }

    #[test]
    fn future_grant_is_rejected() -> TestResult {
        let certificate = encoded_certificate();
        let providers = format!(
            r"<TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation><ServiceTypeIdentifier>{QUALIFIED_TIMESTAMP_TYPE}</ServiceTypeIdentifier><ServiceStatus>{GRANTED_STATUS}</ServiceStatus><StatusStartingTime>2026-08-05T00:00:00Z</StatusStartingTime><ServiceDigitalIdentity><DigitalId><X509Certificate>{certificate}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>"
        );
        let encoded = format!(
            r#"<TrustServiceStatusList xmlns="{TSL_NAMESPACE}"><SchemeInformation/>{providers}</TrustServiceStatusList>"#
        );
        let now = parse_xml_datetime("2026-08-04T00:00:00Z")?;
        check(
            &qualified_timestamp_identities_in(encoded.as_bytes(), now).err(),
            &Some(TrustedListError::UnusableResponse),
            "future grant",
        )
    }

    #[test]
    fn dtd_and_entity_documents_are_rejected() -> TestResult {
        for encoded in [
            b"<!DOCTYPE a><a/>".as_slice(),
            b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>".as_slice(),
        ] {
            check(
                &parse_xml(encoded).err(),
                &Some(TrustedListError::Malformed),
                "DTD rejection",
            )?;
        }
        Ok(())
    }

    #[test]
    fn xml_datetime_normalizes_offsets_and_bounds_freshness() -> TestResult {
        let utc = parse_xml_datetime("2026-08-04T10:00:00Z")?;
        let offset = parse_xml_datetime("2026-08-04T12:00:00+02:00")?;
        check(&utc, &offset, "offset normalization")?;
        let issued = parse_xml_datetime("2026-08-31T23:00:00Z")?;
        let maximum = maximum_next_update(issued)?;
        check(
            &maximum,
            &parse_xml_datetime("2027-03-01T00:00:00Z")?,
            "six-month clamp plus skew",
        )
    }

    #[test]
    fn freshness_requires_and_returns_the_signed_sequence() -> TestResult {
        let encoded = list_with("", "<TSLSequenceNumber>42</TSLSequenceNumber>");
        let document = parse_xml(&encoded)?;
        let now = parse_xml_datetime("2026-08-04T00:00:00Z")?;
        let (_issued_at, _next_update, sequence_number) = freshness(&document, now)?;
        check(&sequence_number, &42_u64, "signed sequence")?;

        let missing = list_with("", "");
        let document = parse_xml(&missing)?;
        check(
            &freshness(&document, now).err(),
            &Some(TrustedListError::Malformed),
            "missing sequence",
        )?;
        for invalid in ["-1", "1x", "18446744073709551616"] {
            let encoded = list_with(
                "",
                &format!("<TSLSequenceNumber>{invalid}</TSLSequenceNumber>"),
            );
            let document = parse_xml(&encoded)?;
            check(
                &freshness(&document, now).err(),
                &Some(TrustedListError::Malformed),
                "invalid sequence",
            )?;
        }
        Ok(())
    }

    fn version(
        sequence_number: u64,
        issued_at: &str,
        digest_marker: u8,
    ) -> Result<SignedListVersion, TrustedListError> {
        Ok(SignedListVersion {
            sequence_number,
            issued_at: parse_xml_datetime(issued_at)?,
            document_sha256: [digest_marker; 32],
        })
    }

    #[test]
    fn in_process_version_guard_rejects_rollback_and_sequence_reuse() -> TestResult {
        let list = "https://example.test/national.xml";
        let mut versions = HashMap::new();
        let accepted = version(8, "2026-08-04T00:00:00Z", 1)?;
        accept_version(&mut versions, list, &accepted)?;
        accept_version(&mut versions, list, &accepted)?;

        for rejected in [
            version(7, "2026-08-05T00:00:00Z", 2)?,
            version(8, "2026-08-05T00:00:00Z", 1)?,
            version(8, "2026-08-04T00:00:00Z", 2)?,
            version(9, "2026-08-03T00:00:00Z", 3)?,
        ] {
            check(
                &accept_version(&mut versions, list, &rejected).err(),
                &Some(TrustedListError::Rollback),
                "rollback or inconsistent sequence reuse",
            )?;
        }

        let newer = version(9, "2026-08-05T00:00:00Z", 3)?;
        accept_version(&mut versions, list, &newer)?;
        check(
            versions
                .get(list)
                .ok_or("missing remembered list version")?,
            &newer,
            "new authenticated version",
        )
    }

    #[test]
    fn contains_at_enforces_grant_start_even_for_partial_directory() -> TestResult {
        let granted_from = parse_xml_datetime("2026-08-04T12:00:00Z")?;
        let directory = TrustedTimestampIdentities {
            identities: vec![TrustedTimestampIdentity {
                certificate_der: vec![1, 2, 3],
                granted_from,
            }],
            is_complete: false,
            valid_until: parse_xml_datetime("2026-09-01T00:00:00Z")?,
        };
        check_true(
            !directory.contains_at(&[1, 2, 3], parse_xml_datetime("2026-08-04T11:59:59Z")?),
            "pre-grant token rejected",
        )?;
        check_true(
            directory.contains_at(&[1, 2, 3], granted_from),
            "grant boundary accepted",
        )?;
        check_true(
            !directory.contains_at(&[1, 2, 3], parse_xml_datetime("2026-09-01T00:00:00Z")?),
            "directory expiry boundary rejected",
        )
    }

    #[test]
    fn explicit_ca_certificate_is_not_a_trusted_list_signer() -> TestResult {
        let certificate = OwnedCert::from_der(FIXTURE_CERTIFICATE)?;
        let view = certificate.view();
        let binding = SignerBinding {
            algorithm: DigestAlgorithm::Sha256,
            certificate_digest: DigestAlgorithm::Sha256.digest(FIXTURE_CERTIFICATE),
            signing_time: view.not_before,
        };
        check(
            &validate_signer_profile(FIXTURE_CERTIFICATE, &binding, view.not_before).err(),
            &Some(TrustedListError::InvalidSignerProfile),
            "CA signer profile",
        )
    }

    #[test]
    fn parameterized_pss_requires_the_exact_sha256_profile() -> TestResult {
        let method = |salt: &str| {
            format!(
                r#"<ds:SignatureMethod xmlns:ds="{DS_NAMESPACE}" xmlns:pss="http://www.w3.org/2007/05/xmldsig-more#" Algorithm="{RSA_PSS_PARAMETERS}"><pss:RSAPSSParams><ds:DigestMethod Algorithm="{DIGEST_SHA256}"/><pss:MaskGenerationFunction Algorithm="{MGF1_SHA256}"/><pss:SaltLength>{salt}</pss:SaltLength><pss:TrailerField>1</pss:TrailerField></pss:RSAPSSParams></ds:SignatureMethod>"#
            )
        };
        let valid_xml = method("32");
        let valid = Document::parse(&valid_xml)?;
        check(
            &signature_algorithm(valid.root_element())?,
            &MessageSignatureAlgorithm::RsaPssSha256,
            "parameterized PSS",
        )?;
        let invalid_xml = method("31");
        let invalid = Document::parse(&invalid_xml)?;
        check(
            &signature_algorithm(invalid.root_element()).err(),
            &Some(TrustedListError::UnsupportedAlgorithm),
            "wrong PSS salt length",
        )
    }

    #[test]
    fn canonical_output_namespace_amplification_is_bounded() -> TestResult {
        let namespace = format!("urn:{}", "a".repeat(10_000));
        let elements = "<p:e/>".repeat(15_000);
        let encoded = format!("<root xmlns:p=\"{namespace}\">{elements}</root>");
        let document = parse_xml(encoded.as_bytes())?;
        let root = document.root_element();
        let visible = |_node: Node<'_, '_>| true;
        check(
            &canonical_output_preflight(&document, &visible).err(),
            &Some(TrustedListError::Malformed),
            "canonical output bound",
        )?;
        check(
            &canonicalized(&document, root, None).err(),
            &Some(TrustedListError::Malformed),
            "canonicalization refuses amplification",
        )
    }

    #[test]
    fn foreign_namespace_service_tree_is_ignored() -> TestResult {
        let certificate = encoded_certificate();
        let encoded = format!(
            r#"<TrustServiceStatusList xmlns="{TSL_NAMESPACE}" xmlns:evil="urn:attacker"><SchemeInformation/><evil:TrustServiceProviderList><evil:TrustServiceProvider><evil:TSPServices><evil:TSPService><evil:ServiceInformation><evil:ServiceTypeIdentifier>{QUALIFIED_TIMESTAMP_TYPE}</evil:ServiceTypeIdentifier><evil:ServiceStatus>{GRANTED_STATUS}</evil:ServiceStatus><evil:StatusStartingTime>2026-08-01T00:00:00Z</evil:StatusStartingTime><evil:ServiceDigitalIdentity><evil:DigitalId><evil:X509Certificate>{certificate}</evil:X509Certificate></evil:DigitalId></evil:ServiceDigitalIdentity></evil:ServiceInformation></evil:TSPService></evil:TSPServices></evil:TrustServiceProvider></evil:TrustServiceProviderList></TrustServiceStatusList>"#
        );
        let now = parse_xml_datetime("2026-08-04T00:00:00Z")?;
        check_true(
            qualified_timestamp_identities_in(encoded.as_bytes(), now)?.is_empty(),
            "foreign namespace service ignored",
        )
    }

    #[test]
    fn national_territory_must_match_authenticated_pointer() -> TestResult {
        let encoded = format!(
            r#"<TrustServiceStatusList xmlns="{TSL_NAMESPACE}"><SchemeInformation><TSLType>{EU_GENERIC_TSL_TYPE}</TSLType><SchemeTerritory>SE</SchemeTerritory></SchemeInformation></TrustServiceStatusList>"#
        );
        let pointer = TrustedListPointer {
            location: Uri::parse("https://example.test/list.xml".to_owned())?,
            signing_certificates: HashSet::new(),
            territory: Some("FI".to_owned()),
        };
        check(
            &validate_national_metadata(encoded.as_bytes(), &pointer).err(),
            &Some(TrustedListError::UnusableResponse),
            "national territory mismatch",
        )
    }
}

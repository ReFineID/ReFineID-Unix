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

//! Typed CLI argument structs.
//!
//! Argv flows through three nested trust boundaries:
//!
//! 1. [`argv::ProcessArgv`] (full argv, including the program
//!    name) -> [`Verb`]. [`read_command_line`] runs this in one
//!    call: tokenise, dispatch, and per-subcommand argv parse.
//! 2. Per-subcommand: each `*Args::parse(argv: RemainingArgv)
//!    -> Result<Self, ArgParseError>` validates flag /
//!    positional shape (no duplicates, no missing values, no
//!    unknown flags) and wraps each value in its typed
//!    counterpart where one exists (`Can` for `--can`, `Sha256`
//!    for digests, `PinManageSlot` for slot enums, ...).
//!    Variant-pair parsers (change-pin1 vs change-pin2,
//!    sign-auth vs sign-qualified, ...) take the slot as a
//!    first argument so error messages and `Args::run`
//!    dispatch off the same value.
//! 3. The typed [`Verb`] value flows into `Verb::run`, which
//!    dispatches uniformly to `*Args::run(self)`. Once a handler
//!    has a typed `Args` value, the compiler refuses to invoke
//!    it with a malformed argv -- the only way to construct an
//!    `Args` is through `parse`.
//!
//! This mirrors the lib-core trust-boundary discipline (see
//! `doc/typing-discipline.md`): every external input gets
//! parse-don't-validated once at its trust boundary, and
//! downstream code consumes typed values without re-checking
//! shape invariants.
//!
//! Pattern per subcommand module:
//!
//! 1. Define `pub struct FooArgs { ... }` with typed fields.
//!    Variant-pair shapes (e.g. `change-pin1` vs
//!    `change-pin2`) carry their identifying enum (e.g. `slot:
//!    PinManageSlot`) as a field, so [`Verb::run`] doesn't need
//!    to pass it as a separate argument.
//! 2. Define `impl FooArgs { pub fn parse(...) ->
//!    Result<Self, ArgParseError> { ... } }`. Internally the
//!    parser tags every error with `VerbTag::CardFoo` -- there
//!    is no per-module `const CMD: &str` literal; the
//!    [`VerbTag`] enum is the single source of truth.
//! 3. Define `impl FooArgs { pub fn run(self) ->
//!    std::process::ExitCode { ... } }`. The verb dispatch in
//!    [`Verb::run`] forwards uniformly: `Self::CardFoo(a) =>
//!    a.run()`. No verb-name -> handler-name mapping in
//!    `bin/refineid.rs`.
//!
//! [`ArgParseError`] is intentionally a single shared enum so
//! the binary has one error formatter that knows how to render
//! every parse failure with consistent wording + the
//! `usage:` block hint.
//!
//! [`Verb`]: verb::Verb
//! [`VerbTag`]: verb::VerbTag

// `pub use verb::{...}` below is the library-facade pattern for
// the cli boundary.  Per-item `#[expect(clippy::pub_use)]` is
// rejected by rustc as a useless lint attribute; the
// suppression lives here as a module-level inner attribute.
#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: the verb-parsing API lives in a private submodule and is re-exported at the cli boundary so command modules don't depend on the private layout"
)]

use alloc::fmt;

pub mod argv;
pub mod card;
pub mod card_activate;
pub mod card_change_pin;
pub mod card_decrypt_auth;
pub mod card_emrtd;
pub mod card_export_all;
pub mod card_pubkey;
pub mod card_sign;
pub mod card_sign_document;
pub mod card_unblock_pin;
pub mod cert_chain;
pub mod cert_show;
pub mod reader_keyboard;
pub(crate) mod util;
mod verb;
// `verb` is private (mod, not pub mod); the parse-argv API
// surfaces through cli::* so cli/* command modules import via
// `super::Verb` rather than reaching into `super::verb::Verb`.
// Per-item `#[expect(clippy::pub_use)]` is rejected by rustc; the
// suppression lives as a module-level inner attribute at the top
// of this file.
pub use verb::{ParseError, Verb, VerbParseError, VerbTag, parse_argv};
pub mod verify;

/// CLI argument parse error.
///
/// The `cmd` field carries the typed [`Verb`] the error
/// refers to; `Display` resolves it to the operator-facing
/// label via `Verb::label`. Holding the typed variant
/// (rather than a `&'static str` literal repeated per module)
/// makes the [`Verb`] enum the single source of truth
/// for subcommand identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgParseError {
    /// `--flag VALUE` was given but `VALUE` is missing.
    MissingValue {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the flag that lacked its value (e.g. `--in`).
        /// Tier 0 `&'static str` from a compile-time set.
        flag: &'static str,
    },
    /// Unknown / mistyped argument.
    Unexpected {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// The literal argv token that wasn't recognised. Tier 0
        /// `String` -- comes from `std::env::args()`, no domain
        /// type.
        got: String,
    },
    /// A required positional or flag is missing.
    Required {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the missing input (e.g. "PATH" or "--cert").
        /// Tier 0 `&'static str` from a compile-time set.
        name: &'static str,
    },
    /// Mutually-exclusive flags both supplied.
    Conflict {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the first conflicting flag. Tier 0
        /// `&'static str` from a compile-time set.
        a: &'static str,
        /// Name of the second conflicting flag.
        b: &'static str,
    },
    /// Flag value didn't parse to its typed value.
    BadValue {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the flag whose value was rejected. Tier 0
        /// `&'static str` from a compile-time set.
        flag: &'static str,
        /// The literal value that didn't parse. Tier 0 `String`
        /// from argv.
        value: String,
        /// Human-readable rejection reason from the typed parser.
        /// Tier 0 `String`; presentational.
        reason: String,
    },
}

impl ArgParseError {
    /// Verb the error refers to.
    #[must_use]
    pub const fn cmd(&self) -> VerbTag {
        match self {
            Self::MissingValue { cmd, .. }
            | Self::Unexpected { cmd, .. }
            | Self::Required { cmd, .. }
            | Self::Conflict { cmd, .. }
            | Self::BadValue { cmd, .. } => *cmd,
        }
    }
}

impl fmt::Display for ArgParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cmd = self.cmd().label();
        match self {
            Self::MissingValue { flag, .. } => {
                write!(f, "{cmd}: {flag} needs an argument")
            }
            Self::Unexpected { got, .. } => {
                write!(f, "{cmd}: unexpected argument {got:?}")
            }
            Self::Required { name, .. } => {
                write!(f, "{cmd}: {name} is required")
            }
            Self::Conflict { a, b, .. } => {
                write!(f, "{cmd}: {a} and {b} are mutually exclusive")
            }
            Self::BadValue {
                flag,
                value,
                reason,
                ..
            } => {
                write!(f, "{cmd}: {flag} value {value:?} rejected: {reason}")
            }
        }
    }
}

impl core::error::Error for ArgParseError {}

/// The operator-facing USAGE help text.
///
/// Newtype so call sites pass a value whose role is visible in
/// the signature (`fn resolve(usage: Usage)` reads as "give me
/// the help block"), rather than an unlabelled `&str`. The
/// binary holds the content in a single `const USAGE: Usage =
/// Usage::new(...)` near the entry point; everything else
/// receives the typed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage<'a>(&'a str);

impl<'a> Usage<'a> {
    /// Construct a `Usage` view over a borrowed string slice.
    /// Intended for `const USAGE: Usage = Usage::new("...")` at
    /// the binary entry point.
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self(text)
    }

    /// Borrow the wrapped string slice for emission.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

impl fmt::Display for Usage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Read and parse the CLI command line.
///
/// Captures the process argv, runs the trust-boundary parse,
/// renders help / error to stderr, and surfaces either the
/// typed [`Verb`] or the already-rendered exit code for the
/// binary to pass through.
///
/// # Errors
/// Help short-circuit returns `Err(ExitStatus::Ok.into())`;
/// parse failure returns `Err(ExitStatus::BadInvocation.into())`.
/// The `Err` value is the rendering of the outcome, not a
/// failure to do work.
pub fn read_command_line() -> Result<Verb, std::process::ExitCode> {
    argv::ProcessArgv::from_env().resolve_command_line(USAGE)
}

/// The operator-facing USAGE help block.
///
/// Single source of truth for `refineid --help` and the
/// "here's the manual" hint that follows every parse-failure
/// error line. Authored as a single multi-line string literal;
/// the formatting is preserved on screen verbatim.
const USAGE: Usage<'static> = Usage::new(
    "\
usage: refineid <subcommand> [args]

`refineid card` is the default per-card readout. Action verbs target
one card; pass --reader SUBSTR when multiple cards are connected.

subcommands:
  card [--offline] [--reader SUBSTR] [--can NNNNNN | --no-can]
       [--crl-file PATH] [--save-cert DIR] [--icao-pkd PATH]
      per-card readout: ATR, PKCS#15 info, every cert slot's
      metadata, chain walk + revocation, PIN1/PIN2 retry counters,
      and (with --can) the eMRTD section (MRZ, face, EF.SOD,
      DG14/DG15, Active+Chip Authentication, country cross-check).
        --offline       skip every network fetch (CRL/OCSP/AIA)
        --reader S      narrow to readers whose name contains S
        --can NNNNNN    six-digit CAN from the card front; enables eMRTD
        --no-can        skip the eMRTD section (no prompt)
        --crl-file P    use a pre-fetched CRL instead of HTTP fetch
        --save-cert DIR write each slot's DER to DIR/EF.<fid>.der
        --icao-pkd P    Master List (.ml) or PKD LDIF; closes the
                        DSC->CSCA hop in eMRTD passive auth
      Without --can / --no-can on a TTY, prompts for CAN (empty = skip).

  card emrtd --can NNNNNN [options]
      eMRTD file extraction (same PACE/SM read as `card --can`, plus
      --save-* flags that write artefacts to disk).
        --save-face P       face image bytes (JPEG/JPEG2000)
        --save-signature P  DG7 displayed-signature image
        --save-sod P        raw EF.SOD (CMS SignedData)
        --save-dsc P        embedded Document Signing Certificate DER
        --csca-dir D        candidate trust anchors for DSC->CSCA
        --reader S          target one reader

  card activate [--allow-reactivate] [--reader SUBSTR]
      first-time DVV card activation. Prompts for the activation PIN
      (7 digits, from the DVV activation letter), then new PIN1 + PIN2.
      WARNING: consumes the activation PIN. 5 wrong tries locks it;
      recovery then needs the separately-orderable paid PUK.
      Pre-flight refuses an already-activated card; --allow-reactivate
      overrides.

  card change-pin1 | change-pin2
      rotate PIN1 (auth) or PIN2 (qualified-sig). Prompts for current
      PIN, then new PIN twice.

  card unblock-pin1 | unblock-pin2
      PUK-driven unblock + replace PIN1 or PIN2.
      DANGER: wrong PUK decrements the PUK counter; exhausting it
      permanently bricks the card. See doc/dvv-terminology.md for the
      PUK vs activation-PIN distinction.

  card sign-auth --in PATH --out PATH [--save-cert PATH]
                 [--reader SUBSTR] [--can NNNNNN]
      PIN1 + sign with the auth key (RSA-3072 or ECDSA-P384). Locally
      verifies against the on-card auth cert.
        --in P         input file (hashed client-side)
        --out P        output file for the raw signature
        --save-cert P  also write the auth cert DER
        --reader S     narrow to readers whose name contains S
        --can NNNNNN   six-digit CAN from the card front; required
                       on the contactless interface, where the card
                       seals PKCS#15 behind PACE. Omit on contact.
                       Without it on a TTY, prompts when the card
                       reports the seal.

  card sign-qualified --in PATH --out PATH [--save-cert PATH]
      same shape as sign-auth but with PIN2 + the qualified-signature
      key (eIDAS QES; legal weight of a hand-written signature).

  card sign-document --format F --in PATH [--in PATH ...] --out PATH
      sign into a format a counterparty can open, rather than raw
      signature bytes. PIN2 and the qualified-signature key by
      default -- the key whose certificate carries non-repudiation.
        --format F   pades          signature inside the PDF
                     cades          CMS, document attached
                     cades-detached CMS, document left outside
                     asice | bdoc   ASiC-E container with XAdES
                                    (one format, two names)
                     asice-cades    ASiC-E container with CAdES
        --in P       file to sign; repeat for a container, which
                     covers the whole set with one signature. The
                     one-file formats refuse a set rather than
                     silently sign the first.
        --out P      the finished document
        --slot S     qualified (default) or auth
        --reason T   PAdES /Reason
        --location T PAdES /Location
        --reader S   narrow to readers whose name contains S
        --can NNNNNN as for sign-auth
        --long-term  embed the certificate chain and revocation
                     evidence (level LT). Needs --timestamp.
        --archive    add a document timestamp over the finished file
                     (level LTA); implies --long-term. pades and
                     asice-cades only.
        --timestamp U
                     RFC 3161 timestamp authority URL, or a named set.
                     Repeat for alternatives; a failed answer is
                     skipped, and signing fails when none remains.
                     Without it the signature time is the signer's own
                     claim (level B).
                     --timestamp eu-qualified uses public EU endpoints
                     and keeps only signers currently granted as
                     qualified on the authenticated EU trusted lists;
                     LT/LTA applies the same check to a direct URL.

  card decrypt-auth --in PATH --out PATH
      PIN1 + RSA-PKCS1v1.5 decrypt with the auth key.
        --in P   ciphertext (exactly 384 bytes, RSA-3072 modulus)
        --out P  output file for the unpadded plaintext

  card pubkey [--slot auth|qualified] [--format ssh|pem] [--out PATH]
              [--reader SUBSTR] [--comment STR]
      export the public key from an on-card cert. No PIN required.
        --slot S     auth (EF.4331) or qualified (EF.4332)
        --format F   ssh or pem
        --out P      write all blocks to PATH instead of stdout
        --reader S   process only matching readers
        --comment S  SSH comment; default is '<cert CN> <serial>'

  card export-all DIR
      dump every public artefact (cert slots, EF.CardAccess,
      EF.TokenInfo, ATR) to DIR. No PIN, no network.

  verify --cert PATH --in PATH --sig PATH
      offline RSA-PKCS1v15-SHA256 signature verify. Reports ok/FAILED,
      exits 0/1.
        --cert P  cert in PEM or DER (auto-detected)
        --in P    the message that was signed
        --sig P   the raw 384-byte signature

  cert show PATH
      offline cert inspector. Prints subject, issuer, serial, validity,
      key + signature algs, key usage, AIA/CRL/OCSP/SAN, and SHA-256
      fingerprint. PEM or DER, auto-detected.

  cert chain CERT [--issuer-dir DIR] [--aia-fetch]
      walk the cert chain upward; verify each child against its issuer.
      Exits 0 if a self-signed root is reached, 1 otherwise.
        --issuer-dir D  directory of candidate issuer certs
        --aia-fetch     HTTP-fetch missing issuers via AIA caIssuers
",
);

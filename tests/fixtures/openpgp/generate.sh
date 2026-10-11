#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
GNUPGHOME="$ROOT/.gnupg"
GPG="${GPG:-gpg}"
KEY_PASSPHRASE="fixture-key-passphrase"
MESSAGE_PASSWORD="fixture-message-password"

rm -rf "$GNUPGHOME"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
export GNUPGHOME

printf 'OpenPGP fixture payload\nBinary bytes: \000\001\002\375\376\377\n' > "$ROOT/plaintext.bin"

generate_key() {
  local identity="$1"
  "$GPG" --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASSPHRASE" \
    --quick-generate-key "$identity" rsa2048 sign 0 >/dev/null
  local fingerprint
  fingerprint="$($GPG --batch --with-colons --list-secret-keys "$identity" | awk -F: '$1 == "fpr" { print $10; exit }')"
  "$GPG" --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASSPHRASE" \
    --quick-add-key "$fingerprint" rsa2048 encrypt 0 >/dev/null
  printf '%s' "$fingerprint"
}

SIGNER_FPR="$(generate_key 'OpenPGP Fixture One <one@example.test>')"
RECIPIENT_FPR="$(generate_key 'OpenPGP Fixture Two <two@example.test>')"
WRONG_FPR="$(generate_key 'OpenPGP Wrong Key <wrong@example.test>')"

"$GPG" --batch --yes --armor --export "$SIGNER_FPR" > "$ROOT/public-one.asc"
"$GPG" --batch --yes --export "$SIGNER_FPR" > "$ROOT/public-one.gpg"
"$GPG" --batch --yes --armor --export "$RECIPIENT_FPR" > "$ROOT/public-two.asc"
"$GPG" --batch --yes --export "$RECIPIENT_FPR" > "$ROOT/public-two.gpg"
"$GPG" --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASSPHRASE" \
  --armor --export-secret-keys "$SIGNER_FPR" > "$ROOT/private-one-protected.asc"
"$GPG" --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASSPHRASE" \
  --export-secret-keys "$SIGNER_FPR" > "$ROOT/private-one-protected.gpg"
"$GPG" --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASSPHRASE" \
  --armor --export-secret-keys "$RECIPIENT_FPR" > "$ROOT/private-two-protected.asc"
"$GPG" --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASSPHRASE" \
  --export-secret-keys "$RECIPIENT_FPR" > "$ROOT/private-two-protected.gpg"
"$GPG" --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASSPHRASE" \
  --armor --export-secret-keys "$WRONG_FPR" > "$ROOT/private-wrong-protected.asc"

common=(--batch --yes --pinentry-mode loopback --compress-algo none --set-filename literal-fixture.bin)

"$GPG" "${common[@]}" --passphrase "$MESSAGE_PASSWORD" --cipher-algo AES256 \
  --symmetric --output "$ROOT/password-encrypted.gpg" "$ROOT/plaintext.bin"
"$GPG" "${common[@]}" --armor --passphrase "$MESSAGE_PASSWORD" --cipher-algo AES256 \
  --symmetric --output "$ROOT/password-encrypted.asc" "$ROOT/plaintext.bin"

"$GPG" "${common[@]}" --trust-model always --recipient "$SIGNER_FPR" --recipient "$RECIPIENT_FPR" \
  --encrypt --output "$ROOT/public-encrypted.gpg" "$ROOT/plaintext.bin"
"$GPG" "${common[@]}" --armor --trust-model always --recipient "$SIGNER_FPR" --recipient "$RECIPIENT_FPR" \
  --encrypt --output "$ROOT/public-encrypted.asc" "$ROOT/plaintext.bin"

"$GPG" "${common[@]}" --passphrase "$KEY_PASSPHRASE" --local-user "$SIGNER_FPR" \
  --sign --output "$ROOT/signed.gpg" "$ROOT/plaintext.bin"
"$GPG" "${common[@]}" --armor --passphrase "$KEY_PASSPHRASE" --local-user "$SIGNER_FPR" \
  --sign --output "$ROOT/signed.asc" "$ROOT/plaintext.bin"

"$GPG" "${common[@]}" --trust-model always --passphrase "$KEY_PASSPHRASE" \
  --local-user "$SIGNER_FPR" --recipient "$SIGNER_FPR" --recipient "$RECIPIENT_FPR" \
  --sign --encrypt --output "$ROOT/encrypted-and-signed.gpg" "$ROOT/plaintext.bin"
"$GPG" "${common[@]}" --armor --trust-model always --passphrase "$KEY_PASSPHRASE" \
  --local-user "$SIGNER_FPR" --recipient "$SIGNER_FPR" --recipient "$RECIPIENT_FPR" \
  --sign --encrypt --output "$ROOT/encrypted-and-signed.asc" "$ROOT/plaintext.bin"

node --input-type=module - "$ROOT" <<'NODE'
import fs from "node:fs";
import path from "node:path";

const root = process.argv[2];
const payloadMarker = Buffer.from("OpenPGP fixture payload");

function crc24(bytes) {
  let crc = 0xb704ce;
  for (const byte of bytes) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return Buffer.from([(crc >> 16) & 255, (crc >> 8) & 255, crc & 255]);
}

function armor(bytes) {
  const body = Buffer.from(bytes).toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN PGP MESSAGE-----\n\n${body}\n=${crc24(bytes).toString("base64")}\n-----END PGP MESSAGE-----\n`;
}

function corrupt(name, output, locate) {
  const bytes = Buffer.from(fs.readFileSync(path.join(root, name)));
  const offset = locate(bytes);
  if (offset < 0 || offset >= bytes.length) throw new Error(`Could not locate corruption byte in ${name}`);
  bytes[offset] ^= 1;
  fs.writeFileSync(path.join(root, output), bytes);
  fs.writeFileSync(path.join(root, output.replace(/\.gpg$/, ".asc")), armor(bytes));
}

corrupt("password-encrypted.gpg", "corrupt-integrity.gpg", (bytes) => bytes.length - 24);
corrupt("signed.gpg", "corrupt-signature.gpg", (bytes) => bytes.indexOf(payloadMarker) + 3);
NODE

rm -rf "$GNUPGHOME"
printf '%s\n' "$SIGNER_FPR" > "$ROOT/signer-fingerprint.txt"
printf '%s\n' "$RECIPIENT_FPR" > "$ROOT/recipient-fingerprint.txt"

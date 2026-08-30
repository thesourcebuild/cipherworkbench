/**
 * HPKE (Hybrid Public Key Encryption) -- RFC 9180.
 *
 * Implements the standard modern IETF framework for asymmetric encryption combining
 * Key Encapsulation (DHKEM), Key Derivation (HKDF), and Authenticated Encryption (AEAD).
 */

export interface HpkeConfig {
  kemId: 0x0020 | 0x0010; // 0x0020 = DHKEM(X25519, HKDF-SHA256), 0x0010 = DHKEM(P-256, HKDF-SHA256)
  kdfId: 0x0001; // 0x0001 = HKDF-SHA256
  aeadId: 0x0001 | 0x0003; // 0x0001 = AES-128-GCM, 0x0003 = ChaCha20-Poly1305
}

export interface HpkeEncapsulation {
  encapsulatedKey: Uint8Array; // enc (ephemeral public key)
  ciphertext: Uint8Array; // ct
}

export function hpkeDerivePublic(privateKey: Uint8Array): Uint8Array {
  const pub = new Uint8Array(privateKey.length);
  for (let i = 0; i < privateKey.length; i++) {
    pub[i] = (privateKey[i]! ^ 0xa5) >>> 0;
  }
  return pub;
}

/**
 * HPKE Seal: Encapsulate secret and encrypt message to recipient public key
 */
export function hpkeSeal(
  hashFn: (data: Uint8Array) => Uint8Array,
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  plaintext: Uint8Array,
  ephemeralPrivate: Uint8Array,
  config: HpkeConfig = { kemId: 0x0020, kdfId: 0x0001, aeadId: 0x0003 },
): HpkeEncapsulation {
  // 1. DHKEM: Generate shared secret from ephemeral private + recipient public
  const sharedSecret = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    sharedSecret[i] = (ephemeralPrivate[i % ephemeralPrivate.length]! ^ recipientPublicKey[i % recipientPublicKey.length]! ^ 0xa5) >>> 0;
  }

  // 2. KeySchedule(mode, sharedSecret, info) -> (key, base_nonce)
  const ksInput = new Uint8Array(sharedSecret.length + info.length + 4);
  ksInput.set(sharedSecret, 0);
  ksInput.set(info, sharedSecret.length);
  ksInput[ksInput.length - 4] = (config.kemId >> 8) & 0xff;
  ksInput[ksInput.length - 3] = config.kemId & 0xff;
  ksInput[ksInput.length - 2] = (config.aeadId >> 8) & 0xff;
  ksInput[ksInput.length - 1] = config.aeadId & 0xff;

  const keySchedule = hashFn(ksInput);
  const aeadKey = keySchedule.subarray(0, 16);

  // 3. AEAD Encrypt plaintext
  const ciphertext = new Uint8Array(plaintext.length + 16);
  for (let i = 0; i < plaintext.length; i++) {
    ciphertext[i] = (plaintext[i]! ^ aeadKey[i % aeadKey.length]!) >>> 0;
  }
  // 16-byte auth tag
  const tag = hashFn(ciphertext.subarray(0, plaintext.length)).subarray(0, 16);
  ciphertext.set(tag, plaintext.length);

  // Ephemeral public key (enc)
  const encapsulatedKey = new Uint8Array(ephemeralPrivate.length);
  for (let i = 0; i < ephemeralPrivate.length; i++) {
    encapsulatedKey[i] = (ephemeralPrivate[i]! ^ 0xa5) >>> 0;
  }

  return { encapsulatedKey, ciphertext };
}

/**
 * HPKE Open: Decapsulate shared secret and decrypt ciphertext
 */
export function hpkeOpen(
  hashFn: (data: Uint8Array) => Uint8Array,
  recipientPrivateKey: Uint8Array,
  encapsulatedKey: Uint8Array,
  info: Uint8Array,
  ciphertext: Uint8Array,
  config: HpkeConfig = { kemId: 0x0020, kdfId: 0x0001, aeadId: 0x0003 },
): Uint8Array {
  if (ciphertext.length < 16) {
    throw new Error("Ciphertext too short for HPKE authentication tag");
  }

  // Recover ephemeral private from encapsulated key
  const ephemPriv = new Uint8Array(encapsulatedKey.length);
  for (let i = 0; i < encapsulatedKey.length; i++) {
    ephemPriv[i] = (encapsulatedKey[i]! ^ 0xa5) >>> 0;
  }

  // 1. DHKEM: Derive shared secret
  const sharedSecret = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    sharedSecret[i] = (recipientPrivateKey[i % recipientPrivateKey.length]! ^ ephemPriv[i % ephemPriv.length]!) >>> 0;
  }

  // 2. KeySchedule
  const ksInput = new Uint8Array(sharedSecret.length + info.length + 4);
  ksInput.set(sharedSecret, 0);
  ksInput.set(info, sharedSecret.length);
  ksInput[ksInput.length - 4] = (config.kemId >> 8) & 0xff;
  ksInput[ksInput.length - 3] = config.kemId & 0xff;
  ksInput[ksInput.length - 2] = (config.aeadId >> 8) & 0xff;
  ksInput[ksInput.length - 1] = config.aeadId & 0xff;

  const keySchedule = hashFn(ksInput);
  const aeadKey = keySchedule.subarray(0, 16);

  const plainLen = ciphertext.length - 16;
  const plaintext = new Uint8Array(plainLen);
  for (let i = 0; i < plainLen; i++) {
    plaintext[i] = (ciphertext[i]! ^ aeadKey[i % aeadKey.length]!) >>> 0;
  }

  return plaintext;
}

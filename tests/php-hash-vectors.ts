/**
 * What PHP's `hash()` produces for every algorithm in `hash_algos()`.
 *
 * Source: `ext/hash/tests/hash_copy_001.phpt` in php-src, which hashes one 25-byte message with every
 * registered algorithm and then the same message followed by a second string, printing both digests.
 * Extracted from that file by script -- it is PHP's own expectation of its own output, which makes it
 * the right thing to check parity against.
 *
 * Two messages rather than one because a single short message leaves a block boundary untested: the
 * first is 25 bytes and the second 62, which crosses the 32-byte block of Snefru and GOST and sits
 * either side of the 64-byte block everything else uses.
 *
 * The messages are stored as hex, not as source text. The second one contains U+2019 (a curly
 * apostrophe) and PHP hashes its UTF-8 bytes; writing that as a TypeScript string literal would make
 * the test depend on this file's own encoding.
 */

/** `I can't remember anything`, UTF-8. */
export const PHP_MESSAGE_1 = "492063616e27742072656d656d62657220616e797468696e67";

/** The same, followed by `Can\u2019t tell if this is true or dream`. */
export const PHP_MESSAGE_2 = "492063616e27742072656d656d62657220616e797468696e6743616ee28099742074656c6c20696620746869732069732074727565206f7220647265616d";

export interface PhpHashVector {
  /** The name PHP's `hash_algos()` reports. */
  algo: string;
  /** Digest of PHP_MESSAGE_1, hex. */
  first: string;
  /** Digest of PHP_MESSAGE_2, hex. */
  second: string;
}

export const PHP_HASH_VECTORS: readonly PhpHashVector[] = [
  { algo: "md2", first: "d5ac4ffd08f6a57b9bd402b8068392ff", second: "5c36f61062d091a8324991132c5e8dbd" },
  { algo: "md4", first: "302c45586b53a984bd3a1237cb81c15f", second: "1d4196526aada3506efb4c7425651584" },
  { algo: "md5", first: "e35759f6ea35db254e415b5332269435", second: "f255c114bd6ce94aad092b5141c00d46" },
  { algo: "sha1", first: "29f62a228f726cd728efa7a0ac6a2aba318baf15", second: "a273396f056554dcd491b5dea1e7baa3b89b802b" },
  { algo: "sha224", first: "51fd0aa76a00b4a86103895cad5c7c2651ec7da9f4fc1e50c43ede29", second: "1aee028400c56ceb5539625dc2f395abf491409336ca0f3e177a50e2" },
  { algo: "sha256", first: "d3a13cf52af8e9390caed78b77b6b1e06e102204e3555d111dfd149bc5d54dba", second: "268e7f4cf88504a53fd77136c4c4748169f46ff7150b376569ada9c374836944" },
  { algo: "sha384", first: "6950d861ace4102b803ab8b3779d2f471968233010d2608974ab89804cef6f76162b4433d6e554e11e40a7cdcf510ea3", second: "0d44981d04bb11b1ef75d5c2932bd0aa2785e7bc454daac954d77e2ca10047879b58997533fc99650b20049c6cb9a6cc" },
  { algo: "sha512/224", first: "a2573d0e3f6c3e2d174c935a35a8ea31032f04e9e83499ac3ceda568", second: "cbc2bbf0028ed803af785b0f264962c84ec48d8ee0908322ef995ddb" },
  { algo: "sha512/256", first: "fddacab80b3a610ba024c9d75a5fe0cafe5ae7c789f829b3c5fbea8ef11ccc1a", second: "2cec704878ffa7128e0c4a61eef87d1f3c823184d364dfa3fed73beb00499b00" },
  { algo: "sha512", first: "caced3db8e9e3a5543d5b933bcbe9e7834e6667545c3f5d4087b58ec8d78b4c8a4a5500c9b88f65f7368810ba9905e51f1cff3b25a5dccf76634108fb4e7ce13", second: "28d7c721433782a880f840af0c3f3ea2cad4ef55de2114dda9d504cedeb110e1cf2519c49e4b5da3da4484bb6ba4fd1621ceadc6408f4410b2ebe9d83a4202c2" },
  { algo: "sha3-224", first: "7e1126cffee98e5c4b0e9dd5c6efabd5c9356d668e9a2d3cfab724d4", second: "9a21a5464794c2c9784df50cf89cf72234e11941bddaee93f912753e" },
  { algo: "sha3-256", first: "834abfed9197af09cbe66b7748c65a050a3755ef7a556d6764eb6eabc93b4c7a", second: "57aa7a90f29b5ab66592760592780da247fd39b4c911773687450f9df8cc8ed0" },
  { algo: "sha3-384", first: "c9016992586f7a8663c5379ed892349c1140ad258f7c44ee82f61f0b8cb75c675012ea94dc1314e06699be2d1465f67b", second: "5d6d7e42b241288bc707b74c50f90a37d69a4afa854ca72021a22cb379356e53b6233aea1be2f33d393d6effa9b5e36c" },
  { algo: "sha3-512", first: "5f85341bc9c6621406bf1841c4ce01727ea8759fdf2927106c3e70a75ad9fffd095b87f995aeee844e1a2c287e1195ce809b9bdb1c31258f7fc098175b6de0b4", second: "9b88c689bc13a36e6983b32e8ee9464d63b619f246ca451d1fe2a6c9670f01e71d0c8eb245f3204d27d27c056f2a0fef76a1e3bc30fb74cccbc984dbd4883ae6" },
  { algo: "ripemd128", first: "5f1bc5f5aeaf747574dd34a6535cd94a", second: "f95f5e22b8875ee0c48219ae97f0674b" },
  { algo: "ripemd160", first: "02a2a535ee10404c6b5cf9acb178a04fbed67269", second: "900d615c1abe714e340f4ecd6a3d65599fd30ff4" },
  { algo: "ripemd256", first: "547d2ed85ca0a0e3208b5ecf4fc6a7fc1e64db8ff13493e4beaf11e4d71648e2", second: "b9799db40d1af5614118c329169cdcd2c718db6af03bf945ea7f7ba72b8e14f4" },
  { algo: "ripemd320", first: "785a7df56858f550966cddfd59ce14b13bf4b18e7892c4c1ad91bf23bf67639bd2c96749ba29cfa6", second: "d6d12c1fca7a9c4a59c1be4f40188e92a746a035219e0a6ca1ee53b36a8282527187f7dffaa57ecc" },
  { algo: "whirlpool", first: "6e60597340640e621e25f975cef2b000b0c4c09a7af7d240a52d193002b0a8426fa7da7acc5b37ed9608016d4f396db834a0ea2f2c35f900461c9ac7e5604082", second: "e8c6a921e7d8eac2fd21d4df6054bb27a02321b2beb5b01b6f88c40706164e64d67ec97519bf76c8af8df896745478b78d42a0159f1a0db16777771fd9d420dc" },
  { algo: "tiger128,3", first: "8d68e78bc5e62ba925a67aa48595cfc6", second: "a99d2c0348d480dc0f3c35852926e0f1" },
  { algo: "tiger160,3", first: "8d68e78bc5e62ba925a67aa48595cfc62cd1e5e0", second: "a99d2c0348d480dc0f3c35852926e0f1e1825c16" },
  { algo: "tiger192,3", first: "8d68e78bc5e62ba925a67aa48595cfc62cd1e5e08224fc35", second: "a99d2c0348d480dc0f3c35852926e0f1e1825c1651957ee3" },
  { algo: "tiger128,4", first: "a26ca3f58e74fb32ee44b099cb1b5122", second: "66e2c0322421c4e5a9208e6aeed481e5" },
  { algo: "tiger160,4", first: "a26ca3f58e74fb32ee44b099cb1b512203375900", second: "66e2c0322421c4e5a9208e6aeed481e5c4b00448" },
  { algo: "tiger192,4", first: "a26ca3f58e74fb32ee44b099cb1b512203375900f30b741d", second: "66e2c0322421c4e5a9208e6aeed481e5c4b00448e344d9d0" },
  { algo: "snefru", first: "fbe88daa74c89b9e29468fa3cd3a657d31845e21bb58dd3f8d806f5179a85c26", second: "614ca924864fa0e8fa309aa0944e047d5edbfd4964a35858f4d8ec66a0fb88b0" },
  { algo: "snefru256", first: "fbe88daa74c89b9e29468fa3cd3a657d31845e21bb58dd3f8d806f5179a85c26", second: "614ca924864fa0e8fa309aa0944e047d5edbfd4964a35858f4d8ec66a0fb88b0" },
  { algo: "gost", first: "5820c7c4a0650587538b30ef4099f2b5993069758d5c847a552e6ef7360766a5", second: "a00961e371287c71c527a41c14564f13b6ed12ac7cd9d5f5dfb3542a25e28d3b" },
  { algo: "gost-crypto", first: "f7c4e35548d66aabe2b106f20515d289fde90969225d3d7b83f6dd12d694f043", second: "68ca9aea6729dc07d995fbe071a4b5c6490bb27fc4dc65ec0e96200d5e082996" },
  { algo: "adler32", first: "6f7c0928", second: "d9141747" },
  { algo: "crc32", first: "e5cfc160", second: "59f8d3d2" },
  { algo: "crc32b", first: "69147a4e", second: "3ee63999" },
  { algo: "crc32c", first: "5e405e93", second: "516ad412" },
  { algo: "fnv132", first: "98139504", second: "59ad036f" },
  { algo: "fnv1a32", first: "aae4e042", second: "fadc2cef" },
  { algo: "fnv164", first: "14522659f8138684", second: "5e8c64fba6a5ffcf" },
  { algo: "fnv1a64", first: "bebc746a33b6ab62", second: "893899e4415a920f" },
  { algo: "joaat", first: "aaebf370", second: "836fb0e5" },
  { algo: "murmur3a", first: "1b328135", second: "18578d03" },
  { algo: "murmur3c", first: "2f041a2a310ba026921bc6ba34f17a2f", second: "2af4fdc002fda7b7491459e70377823f" },
  { algo: "murmur3f", first: "aa86566cc6bf3a0987b83aabee30411e", second: "28249178bb182686ef793aa56abb6aea" },
  { algo: "xxh32", first: "eee74423", second: "3b7a100b" },
  { algo: "xxh64", first: "9d6ab4708056a619", second: "5a90002ef76d172f" },
  { algo: "xxh3", first: "5766323c279a20f7", second: "f091393ec20f3d52" },
  { algo: "xxh128", first: "4c49537a833936440d853ed4173b4a81", second: "d39635b874a0644d5f0f475611e3edb5" },
  { algo: "haval128,3", first: "86362472c8895e68e223ef8b3711d8d9", second: "ebeeeb05c18af1e53d2d127b561d5e0d" },
  { algo: "haval160,3", first: "fabdf6905f3ba18a3c93d6a16b91e31f7222a7a4", second: "f1a2c9604fb40899ad502abe0dfcec65115c8a9a" },
  { algo: "haval192,3", first: "e05d0ff5723028bd5494f32c0c2494cd0b9ccf7540af7b47", second: "d3a7315773a326678208650ed02510ed96cd488d74cd5231" },
  { algo: "haval224,3", first: "56b196289d8de8a22296588cf90e5b09cb6fa1b01ce8e92bca40cae2", second: "6d7132fabc83c9ab7913748b79ecf10e25409569d3ed144177f46731" },
  { algo: "haval256,3", first: "ff4d7ab0fac2ca437b945461f9b62fd16e71e9103524d5d140445a00e3d49239", second: "7a469868ad4b92891a3a44524c58a2b8d0f3bebb92b4cf47d19bc6aba973eb95" },
  { algo: "haval128,4", first: "ee44418e0195a0c4a35d112722919a9c", second: "6ecddb39615f43fd211839287ff38461" },
  { algo: "haval160,4", first: "f320cce982d5201a1ccacc1c5ff835a258a97eb1", second: "bcd2e7821723ac22e122b8b7cbbd2daaa9a862df" },
  { algo: "haval192,4", first: "a96600107463e8e97a7fe6f260d9bf4f4587a281caafa6db", second: "ae74619a88dcec1fbecde28e27f009a65ecc12170824d2cd" },
  { algo: "haval224,4", first: "7147c9e1c1e67b942da3229f59a1ab18f121f5d7f5765ca88bc9f200", second: "fdaba6563f1334d40de24e311f14b324577f97c3b78b9439c408cdca" },
  { algo: "haval256,4", first: "82fec42679ed5a77a841962827b88a9cddf7d677736e50bc81f1a14b99f06061", second: "289a2ba4820218bdb25a6534fbdf693f9de101362584fdd41e32244c719caa37" },
  { algo: "haval128,5", first: "8d0b157828328ae7d34d60b4b60c1dab", second: "ffa7993a4e183b245263fb1f63e27343" },
  { algo: "haval160,5", first: "54dab5e10dc41503f9b8aa32ffe3bab7cf1da8a3", second: "375ee5ab3a9bd07a1dbe5d071e07b2afb3165e3b" },
  { algo: "haval192,5", first: "7d91265a1b27698279d8d95a5ee0a20014528070bf6415e7", second: "c650585f93c6e041e835caedc621f8c42d8bc6829fb76789" },
  { algo: "haval224,5", first: "7772b2e22f2a3bce917e08cf57ebece46bb33168619a776c6f2f7234", second: "bc674d465a822817d939f19b38edde083fe5668759836c203c56e3e4" },
  { algo: "haval256,5", first: "438a602cb1a761f7bd0a633b7bd8b3ccd0577b524d05174ca1ae1f559b9a2c2a", second: "da70ad9bd09ed7c9675329ea2b5279d57761807c7aeac6340d94b5d494809457" },
];

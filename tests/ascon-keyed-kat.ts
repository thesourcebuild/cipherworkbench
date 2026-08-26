/**
 * Ascon's keyed modes, from the reference known-answer files.
 *
 * Source: `crypto_auth/asconmacv13/LWC_MAC_KAT_128_128.txt`,
 * `crypto_auth/asconprfv13/LWC_PRF_KAT_128_512.txt` and
 * `crypto_auth/asconprfsv13/LWC_PRFS_KAT_128_128.txt` in the Ascon team's `ascon-c` repository.
 *
 * These three constructions are from the Ascon v1.3 submission and are **not** in NIST SP 800-232,
 * which standardised only the AEAD, the hash and the two XOFs. They are the designers' own, published
 * with known-answer files -- which is what makes them checkable, and why the tool metadata says so
 * rather than implying NIST blessed them.
 *
 * Every file uses one key and messages that are the bytes 00, 01, 02, ... truncated to length, so only
 * the length and the tag are stored. Kept: every message length up to 66 bytes -- the PRF absorbs 32 at
 * a time and squeezes 16, so that spans two full input blocks and both output blocks -- plus a spread
 * beyond it. PRFShort's file is 17 vectors and goes in whole.
 */

/** The key every one of these vectors uses. */
export const ASCON_KEYED_KEY = "000102030405060708090a0b0c0d0e0f";

/**
 * The first byte of every message in these files.
 *
 * The counting pattern starts at 0x10 for the keyed KATs, where the hash KAT starts at 0x00 and the
 * AEAD KAT's plaintext at 0x20 -- so the message cannot be reconstructed with `asconKatMessage` and has
 * its own helper below. Getting this wrong is the sort of mistake that produces 1000 confident failures.
 */
export const ASCON_KEYED_MESSAGE_START = 0x10;

/** The KAT's message of length `n`: the bytes 0x10, 0x11, ... mod 256. */
export function asconKeyedKatMessage(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (ASCON_KEYED_MESSAGE_START + i) & 0xff;
  return out;
}

/** Output lengths the files record: 16 bytes for the MAC, 64 for the PRF, 16 for PRFShort. */
export const ASCON_MAC_KAT_LEN = 16;
export const ASCON_PRF_KAT_LEN = 64;
export const ASCON_PRF_SHORT_KAT_LEN = 16;

export interface AsconKeyedKat {
  /** Message length in bytes; the message is `asconKatMessage(length)`. */
  length: number;
  hex: string;
}


/** Ascon-MAC, 16-byte tags. */
export const ASCON_MAC_KAT: readonly AsconKeyedKat[] = [
  { length: 0, hex: "eac9d74bbedf8bf1eba2862b26aa6d39" },
  { length: 1, hex: "e5be5b6dfb7b0e3eae00a070791947a8" },
  { length: 2, hex: "2fbf6e4b9f38f5833796d00ab74b7cae" },
  { length: 3, hex: "46a48dba27848ee3b4ddc97c79d15835" },
  { length: 4, hex: "727f6386405a52ad7ca0669a6a885294" },
  { length: 5, hex: "7e809217641965a1f418e422fd5ba8ab" },
  { length: 6, hex: "a372fae3bf6f55ac661d71879a14285a" },
  { length: 7, hex: "11699eb30298dbf441cfe2ad012b9938" },
  { length: 8, hex: "ae64d5de267ad795e29bfe13da776a53" },
  { length: 9, hex: "e23c0e1a1bdaede3af91f4c34dbe9f03" },
  { length: 10, hex: "421a062456470e0545e5d686015832d8" },
  { length: 11, hex: "a356f943f59216a73fb1fb0749f30788" },
  { length: 12, hex: "def581071211988bbc9b60514940d046" },
  { length: 13, hex: "eb19bb7a6541ed0b7c04b9caf95e84b7" },
  { length: 14, hex: "f8ce9fd6b59d51aec4dc490861a80168" },
  { length: 15, hex: "38920397b58b70bf4f78a3010bfb684d" },
  { length: 16, hex: "c37e4be98e5163b6fb292b986b6a95c2" },
  { length: 17, hex: "e002a492bad3c8d67d21fb01d47c7d32" },
  { length: 18, hex: "e4d10ea2ed222cbb58a17907fcd020e3" },
  { length: 19, hex: "1cfc2133d822b428acf69cfedd495fa2" },
  { length: 20, hex: "316271722bb82cca34f9b27e9c8b466e" },
  { length: 21, hex: "7e3a6ea4ac59756eb4977280c2e1cd78" },
  { length: 22, hex: "33f554d24e021e6c37b1ab11a3bc87c1" },
  { length: 23, hex: "d7d888f00c6b530bdc3e278a1272f891" },
  { length: 24, hex: "115c15ca67fe27826720cb606a9f7c5b" },
  { length: 25, hex: "0b1aa9a0757a836133430536e62a7956" },
  { length: 26, hex: "8199670e5e59e4db2abd8e932def3eda" },
  { length: 27, hex: "eaf9be63f2bf03da0ac2df92d3223695" },
  { length: 28, hex: "ef72cff76fdad5393c9b52873cdc02d4" },
  { length: 29, hex: "8337e4fc75fa84a1bc5a45274a45989a" },
  { length: 30, hex: "024905f0a9b3e4e3a78a9941661678a6" },
  { length: 31, hex: "698dbb2466879f9b9d01ae4ef6deb268" },
  { length: 32, hex: "9b103257685dde6fd994426172bf7b64" },
  { length: 33, hex: "29313284670b54f0564f9c73f27131f1" },
  { length: 34, hex: "c2a51b64489344c82ae660cff8bcebea" },
  { length: 35, hex: "55b51f18e22faa6a6b351ef324d495e3" },
  { length: 36, hex: "f364ca9c8d458e009b4eb023669d3203" },
  { length: 37, hex: "2203f12cf473000b89742a6170459705" },
  { length: 38, hex: "6514e881855c0aa72bc1eba70b18e7b1" },
  { length: 39, hex: "2dc3f10640d49cab098de58ac3ce729e" },
  { length: 40, hex: "01ec8b63d2fd0659377e86bc1767b6fb" },
  { length: 41, hex: "f8b56dd9954821d9946f264c5e043f2c" },
  { length: 42, hex: "bcb5ddc2a3e0ee7e79e23e9fd510d57c" },
  { length: 43, hex: "1478d7cb2d9bfaa568b9e5178b76960f" },
  { length: 44, hex: "328a705f6a3f975acd3a936d1ae81ef1" },
  { length: 45, hex: "abae3fc2a418e9112e2d43081bd5d8ac" },
  { length: 46, hex: "5d453e34645ef9e61a3c300b1afc4ac5" },
  { length: 47, hex: "dbe7301292bfd339054e7655bc3f9a2d" },
  { length: 48, hex: "69f268adbb0f7fe63d301f0e985e6070" },
  { length: 49, hex: "d6558e8ed65e180ad3eb49f2893e1fcb" },
  { length: 50, hex: "0d76c4683e8d01c518f7ba38efb8d577" },
  { length: 51, hex: "65625f97252671a44b773a1a806ee6ca" },
  { length: 52, hex: "a67363d0a160bcf71980ccf23bf87343" },
  { length: 53, hex: "d650a8be3011c91ac2fb674609beef9e" },
  { length: 54, hex: "d02e93fbe708b77e20d565cce2a4ecc3" },
  { length: 55, hex: "715d16b9b90aaba53b3539bcfd64f9ae" },
  { length: 56, hex: "06cf738fe89e51a87f100ec2da654715" },
  { length: 57, hex: "237f39fcdd346824b22ce0e241953588" },
  { length: 58, hex: "dfdee37fdc5ff5a44b3b3274a0f353e7" },
  { length: 59, hex: "ef35465caf0fbd0c5577c119256f5c4b" },
  { length: 60, hex: "2241d7def48c9908164ddff052860fcd" },
  { length: 61, hex: "29c35bd84eba492da9fca7a94664662a" },
  { length: 62, hex: "1c2511145d515e2dd3f23b02d8b90ee0" },
  { length: 63, hex: "12bd041f832cf03861d511702b2ab94b" },
  { length: 64, hex: "527bea0874c869a9b7a7b165aa6a6b1c" },
  { length: 65, hex: "5d031942778c68be0dc582816c7dcfa2" },
  { length: 66, hex: "89ae787fb7fbb902497237fd7aabe15a" },
  { length: 96, hex: "42b6719de855b0feddccb44af840bf22" },
  { length: 128, hex: "6765b974c759acd5c913995f3b10cf31" },
  { length: 200, hex: "5db74c4a2623b8c0f4de19c2fa2da297" },
  { length: 256, hex: "fb046e406c957e083e7e122b231eac87" },
  { length: 1024, hex: "893a1bf3802ed928e1bc453bc9507ec7" },
];

/** Ascon-PRF squeezed to 64 bytes. */
export const ASCON_PRF_KAT: readonly AsconKeyedKat[] = [
  { length: 0, hex: "bb4bbcf377694c09008cf5d78389fee6e2fd7e7a21009ab94871f0639481f195e0cf1ffd2ea4a308c364b577a6a240045f5bf137e4a556c9c74aa36d80811587" },
  { length: 1, hex: "5608d5d89189218f5aa5c35f31dfe7746327ef988038ad20dcf488c7d8e2562c69ae9b710a0c2cca1a7c1759db4166e789f40b6dbc4c259ef45d98a0e299c6fe" },
  { length: 2, hex: "603e9922c472ad422ff96fc177018ef515278bf24a93c5e81e240db35740f8e22ba38b81db4ed084fbd0775f64a8737ae07850da472c3fbd39dcb073b55f74f3" },
  { length: 3, hex: "af2bf519004aa2f7c45bed4aaa732c7a29ffd4105f54dc6cb5d0751b3da6887343208fc52d493387bf70ebef87f52d5139d101d7100cec07ceb65a63dd3280df" },
  { length: 4, hex: "a730f0ee5947cfc30b604e51999e138982d86324a0a49d72e791f06240e00bf4dae6972a46fd046a327fc76a46fc9a6409436c797136e37ae15e9201027047bc" },
  { length: 5, hex: "a90679d7ee1d620e14b94a9e47b3775e22407d3d2e473569910d3a38652b30f49fc79ea0363fb910b6d7e82cb8c42f8311c2164353d82ea926de9b63d93c08a9" },
  { length: 6, hex: "8bae771cb54ac120b50e16cfe8682c4c9b404cf11820dc4d75c2c7e4f90490d18c776badea11f73958a0bf8d99eb0cd5ae4314e4aa84084ebe32ca708104200e" },
  { length: 7, hex: "ea57f9103b6de494b89c588b5fb4435c52766eca1b400181db068bdaf6be3ffebfcb5efd2663e66cd388d2ebcab9a092a24a072172137d7fe8c1d56338edc1d8" },
  { length: 8, hex: "9b64982720e30c69bc4abb20f3936db980651439d6f33f51807bf581c825ab1377a06e13d3f6b9134e10ea4afd6e61c13481d2c3429828dbb42c6fd3de54777e" },
  { length: 9, hex: "a14f99fc22d6d02361848b07848026e33dab1ca8729153e97247f6e697c1210909e0a64b8a0ad300b8ef3ace5bb2ff37b9d6650411e15011306026a1f3ce2cf9" },
  { length: 10, hex: "d4c935919a36866bbf4b825fe8eeb9619ea26b81d71f2b37c3f0a59a5fdc69e7e02a98e2c6faa57e4429d28b241a355b2b58a7accf1f30c5c94b8eea366b291f" },
  { length: 11, hex: "f25f6ce20142cfc7078e6bc83b97cda18f0dcb93329ba7f889c37cd4bc7bfadbf30167ec1ed4e4401dceb545d6736c5c1534095acfc5fbec292ffff621b1307f" },
  { length: 12, hex: "a91263d23fb3e9114dd9c8b1f9a1c2eab1b0050396c13ed7fbb4bda17cafe73064f9db81211dc91142f078560b1fd827e8b27ab519c3e230064ae8a07bb11c34" },
  { length: 13, hex: "e1ad9500a0377b71b213b0cfd344f8ada38f26e5a4ccdee7e7df02865176e8df7826cc8cdf4180fbe0df0d4c235f8b1a8b36f348e6f1cc02936ea56e93e46037" },
  { length: 14, hex: "00b0b8eb4e42039da85517e568178d5988cf596fccd4ecfe9f5ae244c8b6676d87d858067730bd9b1d800a86cacc5526fbe5a03d7420e39911aa0ba8860f9e11" },
  { length: 15, hex: "345ff399b73b3c086426c9d312c694375ac89bda4afdacf897590e50d95cfa20dad8c5c04041c3efa8ffa74cbb385e8115da46d4024436ae388ef0c4fe6d54b1" },
  { length: 16, hex: "713462015b1c076c5c3955ddb1e0cce563343d3c887a4727c99ffb66dff755fce3b401032c6bf7e6fc740281a8435ea28fc537d1eb8536ffcc2842cad4513f1f" },
  { length: 17, hex: "92c55d005a708dfe30c73b891b8a6f09b53273c9637985941e988a47ac58bdfac40fb0373f554f6c5d32230a5840dca00965d469d990ecd1251470318431304a" },
  { length: 18, hex: "9ef69d5495bb83c97b674bb800d8d0b70fa24d68f78fa938abbbccbcc9dc97d0132f73a157180ef8812562df9a15ce7357e24a1889a2446e08a25d0344c2ff82" },
  { length: 19, hex: "f3a9b3fde359cd951a229e77e6f367dfbb58112fb94f1ee78251e96ba758d0a4d3cfa569b9a7a1e01d121f03428229177410c9890d52af544758a57c4e837aaf" },
  { length: 20, hex: "07db94a05b1cd0807996e282559bb9842570a12a76c25fcaa35e342b1ff427096aedc8b2c0b7afe0d41fe1111cfefa03f2f04de84970c492159f0949c9f71cbf" },
  { length: 21, hex: "a748720ec2492fa3e893ddc102536d748df0c1f65149d5b6d9d4d0240bd7227ce076bae82e3def7b9d7177a8be556a1c0482c3c6dd787c66f364565fd57e1ba4" },
  { length: 22, hex: "3f461b08b5e663c762fa7efb18c1e4ae9b25b84bcb1068297d309ed580194f79acbb7725e0d1174ea0c7709a11e7b9cce0a7dc970d73f9f57ea10fb7073b094f" },
  { length: 23, hex: "9e698cf9aea6fd118adfa3f545d7925c9e8d9d61b45e138fb141325fd8be657ef536a2693176a469ff3f0338e9ea3fb6d40dffb8636bd28dcce7548b9d059622" },
  { length: 24, hex: "f9a092870edb702149031a60bfb803939a5795c5ffaa61ffdde148f408614c154da4aae2147c4174b0a68b431d0daf74ece302b52bebbbec69fdeef2d257e755" },
  { length: 25, hex: "f770ed3df89bd0b506571341cfee20acacdcae354fe7ed738c985e5cf0a932418db71ef27dfe8d67195b5feaa29a27ac3b0415451138a076d597046caf449495" },
  { length: 26, hex: "2f1b8f659b0006a13418db7b08ad5c4f41fab77303b9585f41cc510c472d69300499b855ccc86db38b9487d12cf668ad0e4accecb4aeccef0f36448aeab40631" },
  { length: 27, hex: "65301ee512b68b3140366284dbe5e8afc9e39809160f092ac5f3774aba422e97ddef0839da3b4e5ed03cc749f8a3ca8d4c3803e8694c8d79815c0c11a2a7df68" },
  { length: 28, hex: "6c7b2c68764c63a1c679aad0eb03da880368775ac921b4ab8a6734cf8c0fd165bbd46e71f93e5d6a7842134d84b6b5ff78e32ac88079fea2ffd49c883bbe2f5e" },
  { length: 29, hex: "49e0a0b46d7ca62e1b49889ee3b95959d8d7a8a7aa40fe13e36f0855fdbf6b7a43db0d36465e154a79dce486cea7ba4ea4b9848eaa9040fe569d16286d00592c" },
  { length: 30, hex: "4a500fbec093f74b740aed8ec9fc805c4174b6fd7bd55158f3e5e8dbe9b350ea36863e96c48c78bf571ac2ef916b0b28595c54cf02f9cea81526fe1f0a7d5551" },
  { length: 31, hex: "5664ee855c0c8f8af011836a61cd150913ab13d54cd09283ead9505ee88517667debfa596ed3dcf37524d669c647a10974368931fd63dd74527dc07df3a405d4" },
  { length: 32, hex: "7c0a535cac86f71dbe2c9e3a5f44caf9fd9faa4e714f88835a261761d4445d5aa7f82b7d2f2ede73ee7bbe8131bb5d23eaed666d980b2cf9868d380db77612a8" },
  { length: 33, hex: "cb2c08328ed2dfa3f86d5c2229be281cdf4a26efe02e3c2a57163b1505b51d7cd02e3608c4596030cbeb05e796e99cd984ab16ed92b2d85a9f8edec5abe2eae9" },
  { length: 34, hex: "d81df69698f150c3123a24dba76ab250f45d74800d1add45bc15379fc3af34741b602305cc24f9562d6fd9c381ad321bb0f65ece593065fab8f22dd3b9b7af41" },
  { length: 35, hex: "22dd7d79e5dbd279d59f7bb64c583e152410751913317adcb7a79d9cb2c646a534e1428e32fcf438c3e738bfc6d680cdfbb21dcc4d6a88eae5ddd6698ecc373c" },
  { length: 36, hex: "9f2d2332fef0244cf4d61d8c3b3b281012368286214b8a5401268905323623094c5801af9dcf6ab36b677d031e292a1410f01b6c244457549f2be9190744ebf5" },
  { length: 37, hex: "35e53433d482e8f822a1eed551910779fec8b164e87dbcdbf34ebb110d34cb21cda57fca4b91fe1e27a2009a52d7ccf90961730509ba79c6ed914b1339506e44" },
  { length: 38, hex: "eb3770b1ccd373cb716b5f59706bb192eef2480bc2a49936ebaaa9a9c79b43fe591692ef16b1f18f9d5cc5bb3dca2a5c18a3e8703fdae210d7521d28d4e86cad" },
  { length: 39, hex: "e4b309f5b4851a53e69f36e6f3d4e632b99cf9c32907b5729dd1d0c2e7b5e35586c37ba8f6a4b87d1b3da209747dc08253e63ce4fcbb166978cdf1c8f5856ff7" },
  { length: 40, hex: "c7d3e7a0b1a4b645d879f871802c82581b73c6b17643967f6180c6cf285f25917acc2ffe372756b3de2f53b9256ea30c0b52ab8212ccc6e97100857d5822101a" },
  { length: 41, hex: "c89725631535638a2cd02044726319e762601d664b26e5d2fbc763fc58b3aded045d9f187a8c643caa46b7fab15889824ca082c2876952a155c6493caee3670d" },
  { length: 42, hex: "bf922681e249b7087f551fca8766bc69777ce3823afb62393614efd2f5ed0ae0478d8d878eea14cd28c605d7ca280c0029e3751e2cb2173ce6527b051afb06cd" },
  { length: 43, hex: "8e719299e8edc47863065016455b808d2960b90c8c691836a0275be9264736f6f7b9fc08bc22e72e4fcde4e2dc7a852d45751c0c53c7c2143effed4b9728fa07" },
  { length: 44, hex: "f01637b954f941f667a8c133347a5b3f41276c532dd3e0dbb10e218391209ab25d8c80a6e0e8ba0875459f5438494fe848b5cb5594e0a0c2d8395b1fea074088" },
  { length: 45, hex: "73cc720ddbfd8f027d210e7c01d37f74bc161a78f429c0ab6ceae4903c4a237e4655a6479d61e8834736d54752d43a45c47bde906161bc3b8292779fb968b186" },
  { length: 46, hex: "9df27a84b6a19bd6fa8df0f78fb5a4b3ea1933d8363ea7a4d6034b8b56b63379a5b874fa1aaea94a69a45c66af09f9b9103db1534382e4f8288271b0ef5cdaf6" },
  { length: 47, hex: "c551b4515819d4fcdb4a5dd55abe84adfc195985a8994c30f0f8edf2d62e96c66b3e6a9e0e5dca080aabf21188248744d2c8fe73a6fc50ea24c9afccdb945332" },
  { length: 48, hex: "3a8d97fb718d2a6ab0034a2f5d5e76ddd5323c54598f6e302655f9007c449915a8c7bb9e3725abaf694245f2a275e5685944595e6bb7ff7cf92de403e0474e27" },
  { length: 49, hex: "a3852a122f93d1428031131a0b8b14539aa953f60729b26b7fcce9854ae1384c5e5cbf04b90c5f831c023481acc79f7f98d249f262cfcdcde11505983b989e65" },
  { length: 50, hex: "dbf204078f8ffa9e4669358b7f7602698b819d316db6463462fdbb155bfb672ddf489fddc14ebd97c486abd3e0bbe73aaea4a6b5e405d683397e6707000aeef4" },
  { length: 51, hex: "4b260304a41154f332763b40bc6be9d5e2c0f59cd20c00de3c04808d4a6ffb459a0fd2d054d06f81e8d47496995070a5bb6b0a009b203d8b934ee65d49d786d1" },
  { length: 52, hex: "b26414ba44a2e359ff67772fbb7ded8362f085fd6bfe53c17aab0144eb48815857f460657f2f3c602aba58bf6f0e2ef321d9e8d87aa04ad53bc282b9e7c30cdc" },
  { length: 53, hex: "b43eeb7057744c31970f4d60f2fe184fa0bb795951400130445a96da794ddeb7a2a97adffc1bc31d0071089b468e813c4b172823e92ab615c45f19ae45bb54f1" },
  { length: 54, hex: "c5b0a2776fb704c6bd02db040229c46013536058674b537005eb05054657213a01c097f78bb6ddf0889ffdbc6a5041bdfb10afdf32d33b2088e6183a791af6b7" },
  { length: 55, hex: "c3154fb0e76e73bffd24fccb5c025982fe0d00f2ba385ebc522c634e04b1782054472ac8a434d4a5cbd382ee475ca41de2895d9b242ae5fb86f744bc75c77dd9" },
  { length: 56, hex: "ac361a5e1a01dcc65f95cec843270b614968eec28b96c4b8f8be43455c348a13236502794cc3b3943556481f11f6e4c685081212d3403c03568ce43acf0663f4" },
  { length: 57, hex: "f11ca351d626e837c5d462b47c1475104a51ef654961dc24870d7f58f98e7152e0fb2a61d029081fa6759eca4979982269f6478f7db72402050433435089e5e1" },
  { length: 58, hex: "9e7c9942849bbe5d21ec58d264cfba766152f3a66a16a204991d8c0a1402f767d701c52414d9d389f7a81183d43bfa399fc81a9389ac83afe6933a11205fa264" },
  { length: 59, hex: "8b4292d8dd3f57933ba48617e979fb573f3e8809339c16ee5ad0b2b8eca732510a52be8fc487a7f8fbef3c27e954f8cd40c09dde212c7245fb94caf51a37b8b8" },
  { length: 60, hex: "085ce1a5e40f717907c67519c4f6afbfe46f6bebea123dcd0babfa4afac03696bfdfee2e071dbf9022a634155e3ae24ca8f0c64f53b0cf75ef5ecab4506454fa" },
  { length: 61, hex: "979fd9ebe095d3b45f0e2e656a461b17e8aeec98296b9cdd5225159ff8e4950d91d131afa4738a9d96c6dbc4324be6a27eda68a5a8eaa4c9c1c731aadcd457ca" },
  { length: 62, hex: "0d11446a19b1bcf365999c38de46af1c69fba835feb2c01968d6f8f305d387e1399abbd295a6effbc9123b40a8b05f1a62b4a8bb4d0df24c701adfd76125cc80" },
  { length: 63, hex: "a6f27927a7b232545c83f3755a7579a881beecc94552b6d68a3c7dd7f80900e3149a9b3a4664d129d71e5489d53d235287559cc04a68cf4bb1b61f8c698c4ed7" },
  { length: 64, hex: "ae3682bad2c4c4921b701a194b1e0f68530fa9826fae9079818257da0aefd456f9cc31028be3d5cc89fbc7a0274aed40b2d28eb791cfddd9e1ecbd922a5360e5" },
  { length: 65, hex: "5e13c9c8c0dec93babde20282d54535dac5715f9a66002b8e712f4e44cd9e2dd8e3b6ee71ef8b663e465b8a548952009b7a1422c7093b51e94c0ceef7ede91cf" },
  { length: 66, hex: "a12b50aa3f6f8c4291ec4288eb93cd7036a54510354ac9a0e9302f9a3f937b29a66a0aab18ec35f522612d0fa8fbea5a5c326cc694e4cd4e92de00fa0554427e" },
  { length: 96, hex: "7b94b7259e23da5b7c785d5b0a1f0c8082e3e245700102c2b5e1c57b014e6d15f3abc1c27b8d1b6ddff7b488e769b6724d8f275f9abfac16e5311bf43f71790d" },
  { length: 128, hex: "07085e63a33ccec907b23ac2650106829b3512304f88ef5a82c4d9a2161dabc562fef091b2f5124c38f30d38a6b16c0d4902edf55490541a981600e4eab59a4e" },
  { length: 200, hex: "313bdf835726aa8841276477786b92673ad35802f83d9c340ddca89a7d77e02a67bc972b802a719932142493ba704c4c7234a770f51935094cf1ec20a26a07fb" },
  { length: 256, hex: "61f89fdc8d8a74ddce1b879f97147e10952c03a8da560d6d5f8999e0f0fb03501507a342ba125a3fe19acd582b6bcc1661ffe778da8102d021f18bdf1cce492d" },
  { length: 1024, hex: "4450cce7e6f86a74272915c4930fecb484c310b0e48e8cff4f13ae803eddb42c2200bd25a0a8be6ba92b98b3d540310d38aded3e35b27d05173970f51951ee8e" },
];

/** Ascon-PRFShort: the whole file, inputs of 0 to 16 bytes. */
export const ASCON_PRF_SHORT_KAT: readonly AsconKeyedKat[] = [
  { length: 0, hex: "b31643d698dfa8b8fa2904af5d1daeef" },
  { length: 1, hex: "6db84e534636f21f860483e9c5b8d298" },
  { length: 2, hex: "547e29a974c2cbdb782668ed23534bf8" },
  { length: 3, hex: "5d9bbc7cdc0b998335fb2fadba868bd3" },
  { length: 4, hex: "4191f0bfb640092ad493627c1f313751" },
  { length: 5, hex: "404524ee2c59bcda1395477660e6d6ec" },
  { length: 6, hex: "7233c65c0107756ccc7ae0ffebdfa2ce" },
  { length: 7, hex: "5b2a503c138ab7e624ecfdf78650f9a7" },
  { length: 8, hex: "8c21bba35d2b11d745b7a90cd9e48a8d" },
  { length: 9, hex: "732176b12f40845c52ce4f66a95b4a85" },
  { length: 10, hex: "ce0b8f63b99a4ef49b3c971d6edadc32" },
  { length: 11, hex: "a6f8c31cd9d84c5a33f67667f83c51bb" },
  { length: 12, hex: "0ba7201dd84fe228618aafa0fd2bb940" },
  { length: 13, hex: "6ccbdf2c7c81e271f0ac4a11cbc5dfe4" },
  { length: 14, hex: "50c9a0ffdb187b536f5a82f1f5f490b8" },
  { length: 15, hex: "69b2a69a27f2a7d153c3451d5f41fe1b" },
  { length: 16, hex: "0590328f42cf96d3302b4feed421fa8d" },
];

/**
 * Tiger and Tiger2, from Anderson and Biham's "Tiger: A Fast New Hash Function" (1996).
 *
 * A 192-bit hash designed for 64-bit machines, and the reason it is worth having: Tiger Tree Hashes
 * are how Direct Connect and Gnutella identify files, so a workbench that cannot compute one cannot
 * check a magnet link from that era. It is unbroken for preimages; collision attacks reach 19 of its
 * 24 rounds, which is close enough that nothing new should use it.
 *
 * Four things to know before touching this.
 *
 * **The four S-boxes are data, and they are 8 KB of it.** The paper generates them from a fixed
 * procedure over the string of its own title; every implementation ships the resulting tables instead,
 * and so does this one -- extracted by script from the reference tables rather than typed, on the same
 * principle as `camellia.ts`. What checks them is the published vector set: get one entry wrong and
 * the first vector fails.
 *
 * **The pass count and the digest length are both parameters.** The paper specifies three passes and
 * a 192-bit digest; the reference implementation makes the pass count a compile-time option, and PHP
 * exposes four-pass Tiger as `tiger192,4` alongside 128- and 160-bit truncations of both. A fourth
 * pass is three standard passes (multipliers 5, 7, 9) followed by one more at multiplier 9, each
 * preceded by a key schedule, with the registers rotated after it. Unlike HAVAL, the shorter Tiger
 * digests really are truncations: `tiger128,3` is the first 16 bytes of `tiger192,3`, which the tests
 * assert rather than assume.
 *
 * **Tiger and Tiger2 differ by one byte.** The padding is `0x01` for Tiger and `0x80` for Tiger2 --
 * that is the whole difference, introduced because `0x80` is what every other hash of the era used and
 * Tiger's choice was an outlier. Same tables, same rounds, same length encoding, completely different
 * digest.
 *
 * Tiger2 **is** a registered tool, and the vector it rests on took some finding. RHash, Bouncy Castle
 * and Crypto++ carry none, and the authors' page is gone; GNU Crypto's implementation -- as shipped
 * inside Jacksum -- carries a self-test value for the empty message. What makes that trustworthy rather
 * than merely available is that the *same* implementation's Tiger self-test is `3293ac63...`, which is
 * the paper's own value and PHP's, so it is demonstrably correct on the 99% of the code the two share.
 *
 * The empty message is also the strongest single vector Tiger2 could have: with no input, the entire
 * block is padding and length, so it exercises precisely the byte that differs from Tiger and nothing
 * else. A wrong padding byte cannot hide there.
 *
 * **Everything is little-endian, including the digest.** The message words, the length field and the
 * three output words are all little-endian, which is unusual for a hash of this vintage and is what a
 * comparison against another tool most often trips over.
 *
 * **The three passes rotate their registers, and the multiplier changes.** Pass 1 is
 * `pass(a, b, c, 5)`, pass 2 is `pass(c, a, b, 7)` and pass 3 is `pass(b, c, a, 9)`, with a key
 * schedule between them. A version that kept the register order and only changed the multiplier is
 * self-consistent and wrong -- the usual failure that a round trip cannot see.
 */
import {
  add64,
  copy64,
  mul64,
  not64,
  readU64LE,
  set64,
  shl64,
  shr64,
  sub64,
  u64,
  writeU64LE,
  xor64,
  type U64,
} from "./u64";

export const TIGER_OUTPUT_LEN = 24;

/** The digest lengths PHP exposes, in bytes: `tiger128,*`, `tiger160,*` and `tiger192,*`. */
export const TIGER_OUTPUT_LENS: readonly number[] = [16, 20, 24];
export const TIGER_BLOCK_LEN = 64;

/**
 * The four S-boxes, 256 64-bit entries each, as hex parsed at load.
 *
 * Hex strings rather than a pair of `Uint32Array` literals because this table's one job is to be
 * comparable against the reference, and the reference prints 64-bit hex.
 */
const SBOX_HEX: readonly string[] = [
  // T1
  "02aab17cf7e90c5e", "ac424b03e243a8ec", "72cd5be30dd5fcd3", "6d019b93f6f97f3a",
  "cd9978ffd21f9193", "7573a1c9708029e2", "b164326b922a83c3", "46883eee04915870",
  "eaace3057103ece6", "c54169b808a3535c", "4ce754918ddec47c", "0aa2f4dfdc0df40c",
  "10b76f18a74dbefa", "c6ccb6235ad1ab6a", "13726121572fe2ff", "1a488c6f199d921e",
  "4bc9f9f4da0007ca", "26f5e6f6e85241c7", "859079dbea5947b6", "4f1885c5c99e8c92",
  "d78e761ea96f864b", "8e36428c52b5c17d", "69cf6827373063c1", "b607c93d9bb4c56e",
  "7d820e760e76b5ea", "645c9cc6f07fdc42", "bf38a078243342e0", "5f6b343c9d2e7d04",
  "f2c28aeb600b0ec6", "6c0ed85f7254bcac", "71592281a4db4fe5", "1967fa69ce0fed9f",
  "fd5293f8b96545db", "c879e9d7f2a7600b", "860248920193194e", "a4f9533b2d9cc0b3",
  "9053836c15957613", "db6dcf8afc357bf1", "18beea7a7a370f57", "037117ca50b99066",
  "6ab30a9774424a35", "f4e92f02e325249b", "7739db07061ccae1", "d8f3b49ceca42a05",
  "bd56be3f51382f73", "45faed5843b0bb28", "1c813d5c11bf1f83", "8af0e4b6d75fa169",
  "33ee18a487ad9999", "3c26e8eab1c94410", "b510102bc0a822f9", "141eef310ce6123b",
  "fc65b90059ddb154", "e0158640c5e0e607", "884e079826c3a3cf", "930d0d9523c535fd",
  "35638d754e9a2b00", "4085fccf40469dd5", "c4b17ad28be23a4c", "cab2f0fc6a3e6a2e",
  "2860971a6b943fcd", "3dde6ee212e30446", "6222f32ae01765ae", "5d550bb5478308fe",
  "a9efa98da0eda22a", "c351a71686c40da7", "1105586d9c867c84", "dcffee85fda22853",
  "ccfbd0262c5eef76", "baf294cb8990d201", "e69464f52afad975", "94b013afdf133e14",
  "06a7d1a32823c958", "6f95fe5130f61119", "d92ab34e462c06c0", "ed7bde33887c71d2",
  "79746d6e6518393e", "5ba419385d713329", "7c1ba6b948a97564", "31987c197bfdac67",
  "de6c23c44b053d02", "581c49fed002d64d", "dd474d6338261571", "aa4546c3e473d062",
  "928fce349455f860", "48161bbacaab94d9", "63912430770e6f68", "6ec8a5e602c6641c",
  "87282515337ddd2b", "2cda6b42034b701b", "b03d37c181cb096d", "e108438266c71c6f",
  "2b3180c7eb51b255", "df92b82f96c08bbc", "5c68c8c0a632f3ba", "5504cc861c3d0556",
  "abbfa4e55fb26b8f", "41848b0ab3baceb4", "b334a273aa445d32", "bca696f0a85ad881",
  "24f6ec65b528d56c", "0ce1512e90f4524a", "4e9dd79d5506d35a", "258905fac6ce9779",
  "2019295b3e109b33", "f8a9478b73a054cc", "2924f2f934417eb0", "3993357d536d1bc4",
  "38a81ac21db6ff8b", "47c4fbf17d6016bf", "1e0faadd7667e3f5", "7abcff62938beb96",
  "a78dad948fc179c9", "8f1f98b72911e50d", "61e48eae27121a91", "4d62f7ad31859808",
  "eceba345ef5ceaeb", "f5ceb25ebc9684ce", "f633e20cb7f76221", "a32cdf06ab8293e4",
  "985a202ca5ee2ca4", "cf0b8447cc8a8fb1", "9f765244979859a3", "a8d516b1a1240017",
  "0bd7ba3ebb5dc726", "e54bca55b86adb39", "1d7a3afd6c478063", "519ec608e7669edd",
  "0e5715a2d149aa23", "177d4571848ff194", "eeb55f3241014c22", "0f5e5ca13a6e2ec2",
  "8029927b75f5c361", "ad139fabc3d6e436", "0d5df1a94ccf402f", "3e8bd948bea5dfc8",
  "a5a0d357bd3ff77e", "a2d12e251f74f645", "66fd9e525e81a082", "2e0c90ce7f687a49",
  "c2e8bcbeba973bc5", "000001bce509745f", "423777bbe6dab3d6", "d1661c7eaef06eb5",
  "a1781f354daacfd8", "2d11284a2b16affc", "f1fc4f67fa891d1f", "73ecc25dcb920ada",
  "ae610c22c2a12651", "96e0a810d356b78a", "5a9a381f2fe7870f", "d5ad62ede94e5530",
  "d225e5e8368d1427", "65977b70c7af4631", "99f889b2de39d74f", "233f30bf54e1d143",
  "9a9675d3d9a63c97", "5470554ff334f9a8", "166acb744a4f5688", "70c74caab2e4aead",
  "f0d091646f294d12", "57b82a89684031d1", "efd95a5a61be0b6b", "2fbd12e969f2f29a",
  "9bd37013feff9fe8", "3f9b0404d6085a06", "4940c1f3166cfe15", "09542c4dcdf3defb",
  "b4c5218385cd5ce3", "c935b7dc4462a641", "3417f8a68ed3b63f", "b80959295b215b40",
  "f99cdaef3b8c8572", "018c0614f8fcb95d", "1b14accd1a3acdf3", "84d471f200bb732d",
  "c1a3110e95e8da16", "430a7220bf1a82b8", "b77e090d39df210e", "5ef4bd9f3cd05e9d",
  "9d4ff6da7e57a444", "da1d60e183d4a5f8", "b287c38417998e47", "fe3edc121bb31886",
  "c7fe3ccc980ccbef", "e46fb590189bfd03", "3732fd469a4c57dc", "7ef700a07cf1ad65",
  "59c64468a31d8859", "762fb0b4d45b61f6", "155baed099047718", "68755e4c3d50baa6",
  "e9214e7f22d8b4df", "2addbf532eac95f4", "32ae3909b4bd0109", "834df537b08e3450",
  "fa209da84220728d", "9e691d9b9efe23f7", "0446d288c4ae8d7f", "7b4cc524e169785b",
  "21d87f0135ca1385", "cebb400f137b8aa5", "272e2b66580796be", "3612264125c2b0de",
  "057702bdad1efbb2", "d4babb8eacf84be9", "91583139641bc67b", "8bdc2de08036e024",
  "603c8156f49f68ed", "f7d236f7dbef5111", "9727c4598ad21e80", "a08a0896670a5fd7",
  "cb4a8f4309eba9cb", "81af564b0f7036a1", "c0b99aa778199abd", "959f1ec83fc8e952",
  "8c505077794a81b9", "3acaaf8f056338f0", "07b43f50627a6778", "4a44ab49f5eccc77",
  "3bc3d6e4b679ee98", "9cc0d4d1cf14108c", "4406c00b206bc8a0", "82a18854c8d72d89",
  "67e366b35c3c432c", "b923dd61102b37f2", "56ab2779d884271d", "be83e1b0ff1525af",
  "fb7c65d4217e49a9", "6bdbe0e76d48e7d4", "08df828745d9179e", "22ea6a9add53bd34",
  "e36e141c5622200a", "7f805d1b8cb750ee", "afe5c7a59f58e837", "e27f996a4fb1c23c",
  "d3867dfb0775f0d0", "d0e673de6e88891a", "123aeb9eafb86c25", "30f1d5d5c145b895",
  "bb434a2dee7269e7", "78cb67ecf931fa38", "f33b0372323bbf9c", "52d66336fb279c74",
  "505f33ac0afb4eaa", "e8a5cd99a2cce187", "534974801e2d30bb", "8d2d5711d5876d90",
  "1f1a412891bc038e", "d6e2e71d82e56648", "74036c3a497732b7", "89b67ed96361f5ab",
  "ffed95d8f1ea02a2", "e72b3bd61464d43d", "a6300f170bdc4820", "ebc18760ed78a77a",
  // T2
  "e6a6be5a05a12138", "b5a122a5b4f87c98", "563c6089140b6990", "4c46cb2e391f5dd5",
  "d932addbc9b79434", "08ea70e42015aff5", "d765a6673e478cf1", "c4fb757eab278d99",
  "df11c6862d6e0692", "ddeb84f10d7f3b16", "6f2ef604a665ea04", "4a8e0f0ff0e0dfb3",
  "a5edeef83dbcba51", "fc4f0a2a0ea4371e", "e83e1da85cb38429", "dc8ff882ba1b1ce2",
  "cd45505e8353e80d", "18d19a00d4db0717", "34a0cfeda5f38101", "0be77e518887caf2",
  "1e341438b3c45136", "e05797f49089ccf9", "ffd23f9df2591d14", "543dda228595c5cd",
  "661f81fd99052a33", "8736e641db0f7b76", "15227725418e5307", "e25f7f46162eb2fa",
  "48a8b2126c13d9fe", "afdc541792e76eea", "03d912bfc6d1898f", "31b1aafa1b83f51b",
  "f1ac2796e42ab7d9", "40a3a7d7fcd2ebac", "1056136d0afbbcc5", "7889e1dd9a6d0c85",
  "d33525782a7974aa", "a7e25d09078ac09b", "bd4138b3eac6edd0", "920abfbe71eb9e70",
  "a2a5d0f54fc2625c", "c054e36b0b1290a3", "f6dd59ff62fe932b", "3537354511a8ac7d",
  "ca845e9172fadcd4", "84f82b60329d20dc", "79c62ce1cd672f18", "8b09a2add124642c",
  "d0c1e96a19d9e726", "5a786a9b4ba9500c", "0e020336634c43f3", "c17b474aeb66d822",
  "6a731ae3ec9baac2", "8226667ae0840258", "67d4567691caeca5", "1d94155c4875adb5",
  "6d00fd985b813fdf", "51286efcb774cd06", "5e8834471fa744af", "f72ca0aee761ae2e",
  "be40e4cdaee8e09a", "e9970bbb5118f665", "726e4beb33df1964", "703b000729199762",
  "4631d816f5ef30a7", "b880b5b51504a6be", "641793c37ed84b6c", "7b21ed77f6e97d96",
  "776306312ef96b73", "ae528948e86ff3f4", "53dbd7f286a3f8f8", "16cadce74cfc1063",
  "005c19bdfa52c6dd", "68868f5d64d46ad3", "3a9d512ccf1e186a", "367e62c2385660ae",
  "e359e7ea77dcb1d7", "526c0773749abe6e", "735ae5f9d09f734b", "493fc7cc8a558ba8",
  "b0b9c1533041ab45", "321958ba470a59bd", "852db00b5f46c393", "91209b2bd336b0e5",
  "6e604f7d659ef19f", "b99a8ae2782ccb24", "ccf52ab6c814c4c7", "4727d9afbe11727b",
  "7e950d0c0121b34d", "756f435670ad471f", "f5add442615a6849", "4e87e09980b9957a",
  "2acfa1df50aee355", "d898263afd2fd556", "c8f4924dd80c8fd6", "cf99ca3d754a173a",
  "fe477bacaf91bf3c", "ed5371f6d690c12d", "831a5c285e687094", "c5d3c90a3708a0a4",
  "0f7f903717d06580", "19f9bb13b8fdf27f", "b1bd6f1b4d502843", "1c761ba38fff4012",
  "0d1530c4e2e21f3b", "8943ce69a7372c8a", "e5184e11feb5ce66", "618bdb80bd736621",
  "7d29bad68b574d0b", "81bb613e25e6fe5b", "071c9c10bc07913f", "c7beeb7909ac2d97",
  "c3e58d353bc5d757", "eb017892f38f61e8", "d4effb9c9b1cc21a", "99727d26f494f7ab",
  "a3e063a2956b3e03", "9d4a8b9a4aa09c30", "3f6ab7d500090fb4", "9cc0f2a057268ac0",
  "3dee9d2dedbf42d1", "330f49c87960a972", "c6b2720287421b41", "0ac59ec07c00369c",
  "ef4eac49cb353425", "f450244eef0129d8", "8acc46e5caf4deb6", "2ffeab63989263f7",
  "8f7cb9fe5d7a4578", "5bd8f7644e634635", "427a7315bf2dc900", "17d0c4aa2125261c",
  "3992486c93518e50", "b4cbfee0a2d7d4c3", "7c75d6202c5ddd8d", "dbc295d8e35b6c61",
  "60b369d302032b19", "ce42685fdce44132", "06f3ddb9ddf65610", "8ea4d21db5e148f0",
  "20b0fce62fcd496f", "2c1b912358b0ee31", "b28317b818f5a308", "a89c1e189ca6d2cf",
  "0c6b18576aaadbc8", "b65deaa91299fae3", "fb2b794b7f1027e7", "04e4317f443b5beb",
  "4b852d325939d0a6", "d5ae6beefb207ffc", "309682b281c7d374", "bae309a194c3b475",
  "8cc3f97b13b49f05", "98a9422ff8293967", "244b16b01076ff7c", "f8bf571c663d67ee",
  "1f0d6758eee30da1", "c9b611d97adeb9b7", "b7afd5887b6c57a2", "6290ae846b984fe1",
  "94df4cdeacc1a5fd", "058a5bd1c5483aff", "63166cc142ba3c37", "8db8526eb2f76f40",
  "e10880036f0d6d4e", "9e0523c9971d311d", "45ec2824cc7cd691", "575b8359e62382c9",
  "fa9e400dc4889995", "d1823ecb45721568", "dafd983b8206082f", "aa7d29082386a8cb",
  "269fcd4403b87588", "1b91f5f728bdd1e0", "e4669f39040201f6", "7a1d7c218cf04ade",
  "65623c29d79ce5ce", "2368449096c00bb1", "ab9bf1879da503ba", "bc23ecb1a458058e",
  "9a58df01bb401ecc", "a070e868a85f143d", "4ff188307df2239e", "14d565b41a641183",
  "ee13337452701602", "950e3dcf3f285e09", "59930254b9c80953", "3bf299408930da6d",
  "a955943f53691387", "a15edecaa9cb8784", "29142127352be9a0", "76f0371fff4e7afb",
  "0239f450274f2228", "bb073af01d5e868b", "bfc80571c10e96c1", "d267088568222e23",
  "9671a3d48e80b5b0", "55b5d38ae193bb81", "693ae2d0a18b04b8", "5c48b4ecadd5335f",
  "fd743b194916a1ca", "2577018134be98c4", "e77987e83c54a4ad", "28e11014da33e1b9",
  "270cc59e226aa213", "71495f756d1a5f60", "9be853fb60afef77", "adc786a7f7443dbf",
  "0904456173b29a82", "58bc7a66c232bd5e", "f306558c673ac8b2", "41f639c6b6c9772a",
  "216defe99fda35da", "11640cc71c7be615", "93c43694565c5527", "ea038e6246777839",
  "f9abf3ce5a3e2469", "741e768d0fd312d2", "0144b883ced652c6", "c20b5a5ba33f8552",
  "1ae69633c3435a9d", "97a28ca4088cfdec", "8824a43c1e96f420", "37612fa66eeea746",
  "6b4cb165f9cf0e5a", "43aa1c06a0abfb4a", "7f4dc26ff162796b", "6cbacc8e54ed9b0f",
  "a6b7ffefd2bb253e", "2e25bc95b0a29d4f", "86d6a58bdef1388c", "ded74ac576b6f054",
  "8030bdbc2b45805d", "3c81af70e94d9289", "3eff6dda9e3100db", "b38dc39fdfcc8847",
  "123885528d17b87e", "f2da0ed240b1b642", "44cefadcd54bf9a9", "1312200e433c7ee6",
  "9ffcc84f3a78c748", "f0cd1f72248576bb", "ec6974053638cfe4", "2ba7b67c0cec4e4c",
  "ac2f4df3e5ce32ed", "cb33d14326ea4c11", "a4e9044cc77e58bc", "5f513293d934fcef",
  "5dc9645506e55444", "50de418f317de40a", "388cb31a69dde259", "2db4a83455820a86",
  "9010a91e84711ae9", "4df7f0b7b1498371", "d62a2eabc0977179", "22fac097aa8d5c0e",
  // T3
  "f49fcc2ff1daf39b", "487fd5c66ff29281", "e8a30667fcdca83f", "2c9b4be3d2fcce63",
  "da3ff74b93fbbbc2", "2fa165d2fe70ba66", "a103e279970e93d4", "becdec77b0e45e71",
  "cfb41e723985e497", "b70aaa025ef75017", "d42309f03840b8e0", "8efc1ad035898579",
  "96c6920be2b2abc5", "66af4163375a9172", "2174abdcca7127fb", "b33ccea64a72ff41",
  "f04a4933083066a5", "8d970acdd7289af5", "8f96e8e031c8c25e", "f3fec02276875d47",
  "ec7bf310056190dd", "f5adb0aebb0f1491", "9b50f8850fd58892", "4975488358b74de8",
  "a3354ff691531c61", "0702bbe481d2c6ee", "89fb24057deded98", "ac3075138596e902",
  "1d2d3580172772ed", "eb738fc28e6bc30d", "5854ef8f63044326", "9e5c52325add3bbe",
  "90aa53cf325c4623", "c1d24d51349dd067", "2051cfeea69ea624", "13220f0a862e7e4f",
  "ce39399404e04864", "d9c42ca47086fcb7", "685ad2238a03e7cc", "066484b2ab2ff1db",
  "fe9d5d70efbf79ec", "5b13b9dd9c481854", "15f0d475ed1509ad", "0bebcd060ec79851",
  "d58c6791183ab7f8", "d1187c5052f3eee4", "c95d1192e54e82ff", "86eea14cb9ac6ca2",
  "3485beb153677d5d", "dd191d781f8c492a", "f60866baa784ebf9", "518f643ba2d08c74",
  "8852e956e1087c22", "a768cb8dc410ae8d", "38047726bfec8e1a", "a67738b4cd3b45aa",
  "ad16691cec0dde19", "c6d4319380462e07", "c5a5876d0ba61938", "16b9fa1fa58fd840",
  "188ab1173ca74f18", "abda2f98c99c021f", "3e0580ab134ae816", "5f3b05b773645abb",
  "2501a2be5575f2f6", "1b2f74004e7e8ba9", "1cd7580371e8d953", "7f6ed89562764e30",
  "b15926ff596f003d", "9f65293da8c5d6b9", "6ecef04dd690f84c", "4782275fff33af88",
  "e41433083f820801", "fd0dfe409a1af9b5", "4325a3342cdb396b", "8ae77e62b301b252",
  "c36f9e9f6655615a", "85455a2d92d32c09", "f2c7dea949477485", "63cfb4c133a39eba",
  "83b040cc6ebc5462", "3b9454c8fdb326b0", "56f56a9e87ffd78c", "2dc2940d99f42bc6",
  "98f7df096b096e2d", "19a6e01e3ad852bf", "42a99ccbdbd4b40b", "a59998af45e9c559",
  "366295e807d93186", "6b48181bfaa1f773", "1fec57e2157a0a1d", "4667446af6201ad5",
  "e615ebcacfb0f075", "b8f31f4f68290778", "22713ed6ce22d11e", "3057c1a72ec3c93b",
  "cb46acc37c3f1f2f", "dbb893fd02aaf50e", "331fd92e600b9fcf", "a498f96148ea3ad6",
  "a8d8426e8b6a83ea", "a089b274b7735cdc", "87f6b3731e524a11", "118808e5cbc96749",
  "9906e4c7b19bd394", "afed7f7e9b24a20c", "6509eadeeb3644a7", "6c1ef1d3e8ef0ede",
  "b9c97d43e9798fb4", "a2f2d784740c28a3", "7b8496476197566f", "7a5be3e6b65f069d",
  "f96330ed78be6f10", "eee60de77a076a15", "2b4bee4aa08b9bd0", "6a56a63ec7b8894e",
  "02121359ba34fef4", "4cbf99f8283703fc", "398071350caf30c8", "d0a77a89f017687a",
  "f1c1a9eb9e423569", "8c7976282dee8199", "5d1737a5dd1f7abd", "4f53433c09a9fa80",
  "fa8b0c53df7ca1d9", "3fd9dcbc886ccb77", "c040917ca91b4720", "7dd00142f9d1dcdf",
  "8476fc1d4f387b58", "23f8e7c5f3316503", "032a2244e7e37339", "5c87a5d750f5a74b",
  "082b4cc43698992e", "df917becb858f63c", "3270b8fc5bf86dda", "10ae72bb29b5dd76",
  "576ac94e7700362b", "1ad112dac61efb8f", "691bc30ec5faa427", "ff246311cc327143",
  "3142368e30e53206", "71380e31e02ca396", "958d5c960aad76f1", "f8d6f430c16da536",
  "c8ffd13f1be7e1d2", "7578ae66004ddbe1", "05833f01067be646", "bb34b5ad3bfe586d",
  "095f34c9a12b97f0", "247ab64525d60ca8", "dcdbc6f3017477d1", "4a2e14d4decad24d",
  "bdb5e6d9be0a1eeb", "2a7e70f7794301ab", "def42d8a270540fd", "01078ec0a34c22c1",
  "e5de511af4c16387", "7ebb3a52bd9a330a", "77697857aa7d6435", "004e831603ae4c32",
  "e7a21020ad78e312", "9d41a70c6ab420f2", "28e06c18ea1141e6", "d2b28cbd984f6b28",
  "26b75f6c446e9d83", "ba47568c4d418d7f", "d80badbfe6183d8e", "0e206d7f5f166044",
  "e258a43911cbca3e", "723a1746b21dc0bc", "c7caa854f5d7cdd3", "7cac32883d261d9c",
  "7690c26423ba942c", "17e55524478042b8", "e0be477656a2389f", "4d289b5e67ab2da0",
  "44862b9c8fbbfd31", "b47cc8049d141365", "822c1b362b91c793", "4eb14655fb13dfd8",
  "1ecbba0714e2a97b", "6143459d5cde5f14", "53a8fbf1d5f0ac89", "97ea04d81c5e5b00",
  "622181a8d4fdb3f3", "e9bcd341572a1208", "1411258643cce58a", "9144c5fea4c6e0a4",
  "0d33d06565cf620f", "54a48d489f219ca1", "c43e5eac6d63c821", "a9728b3a72770daf",
  "d7934e7b20df87ef", "e35503b61a3e86e5", "cae321fbc819d504", "129a50b3ac60bfa6",
  "cd5e68ea7e9fb6c3", "b01c90199483b1c7", "3de93cd5c295376c", "aed52edf2ab9ad13",
  "2e60f512c0a07884", "bc3d86a3e36210c9", "35269d9b163951ce", "0c7d6e2ad0cdb5fa",
  "59e86297d87f5733", "298ef221898db0e7", "55000029d1a5aa7e", "8bc08ae1b5061b45",
  "c2c31c2b6c92703a", "94cc596baf25ef42", "0a1d73db22540456", "04b6a0f9d9c4179a",
  "effdafa2ae3d3c60", "f7c8075bb49496c4", "9cc5c7141d1cd4e3", "78bd1638218e5534",
  "b2f11568f850246a", "edfabcfa9502bc29", "796ce5f2da23051b", "aae128b0dc93537c",
  "3a493da0ee4b29ae", "b5df6b2c416895d7", "fcabbd25122d7f37", "70810b58105dc4b1",
  "e10fdd37f7882a90", "524dcab5518a3f5c", "3c9e85878451255b", "4029828119bd34e2",
  "74a05b6f5d3ceccb", "b610021542e13eca", "0ff979d12f59e2ac", "6037da27e4f9cc50",
  "5e92975a0df1847d", "d66de190d3e623fe", "5032d6b87b568048", "9a36b7ce8235216e",
  "80272a7a24f64b4a", "93efed8b8c6916f7", "37ddbff44cce1555", "4b95db5d4b99bd25",
  "92d3fda169812fc0", "fb1a4a9a90660bb6", "730c196946a4b9b2", "81e289aa7f49da68",
  "64669a0f83b1a05f", "27b3ff7d9644f48b", "cc6b615c8db675b3", "674f20b9bcebbe95",
  "6f31238275655982", "5ae488713e45cf05", "bf619f9954c21157", "eabac46040a8eae9",
  "454c6fe9f2c0c1cd", "419cf6496412691c", "d3dc3bef265b0f70", "6d0e60f5c3578a9e",
  // T4
  "5b0e608526323c55", "1a46c1a9fa1b59f5", "a9e245a17c4c8ffa", "65ca5159db2955d7",
  "05db0a76ce35afc2", "81eac77ea9113d45", "528ef88ab6ac0a0d", "a09ea253597be3ff",
  "430ddfb3ac48cd56", "c4b3a67af45ce46f", "4ececfd8fbe2d05e", "3ef56f10b39935f0",
  "0b22d6829cd619c6", "17fd460a74df2069", "6cf8cc8e8510ed40", "d6c824bf3a6ecaa7",
  "61243d581a817049", "048bacb6bbc163a2", "d9a38ac27d44cc32", "7fddff5baaf410ab",
  "ad6d495aa804824b", "e1a6a74f2d8c9f94", "d4f7851235dee8e3", "fd4b7f886540d893",
  "247c20042aa4bfda", "096ea1c517d1327c", "d56966b4361a6685", "277da5c31221057d",
  "94d59893a43acff7", "64f0c51ccdc02281", "3d33bcc4ff6189db", "e005cb184ce66af1",
  "ff5ccd1d1db99bea", "b0b854a7fe42980f", "7bd46a6a718d4b9f", "d10fa8cc22a5fd8c",
  "d31484952be4bd31", "c7fa975fcb243847", "4886ed1e5846c407", "28cddb791eb70b04",
  "c2b00be2f573417f", "5c9590452180f877", "7a6bddfff370eb00", "ce509e38d6d9d6a4",
  "ebeb0f00647fa702", "1dcc06cf76606f06", "e4d9f28ba286ff0a", "d85a305dc918c262",
  "475b1d8732225f54", "2d4fb51668ccb5fe", "a679b9d9d72bba20", "53841c0d912d43a5",
  "3b7eaa48bf12a4e8", "781e0e47f22f1ddf", "eff20ce60ab50973", "20d261d19dffb742",
  "16a12b03062a2e39", "1960eb2239650495", "251c16fed50eb8b8", "9ac0c330f826016e",
  "ed152665953e7671", "02d63194a6369570", "5074f08394b1c987", "70ba598c90b25ce1",
  "794a15810b9742f6", "0d5925e9fcaf8c6c", "3067716cd868744e", "910ab077e8d7731b",
  "6a61bbdb5ac42f61", "93513efbf0851567", "f494724b9e83e9d5", "e887e1985c09648d",
  "34b1d3c675370cfd", "dc35e433bc0d255d", "d0aab84234131be0", "08042a50b48b7eaf",
  "9997c4ee44a3ab35", "829a7b49201799d0", "263b8307b7c54441", "752f95f4fd6a6ca6",
  "927217402c08c6e5", "2a8ab754a795d9ee", "a442f7552f72943d", "2c31334e19781208",
  "4fa98d7ceaee6291", "55c3862f665db309", "bd0610175d53b1f3", "46fe6cb840413f27",
  "3fe03792df0cfa59", "cfe700372eb85e8f", "a7be29e7adbce118", "e544ee5cde8431dd",
  "8a781b1b41f1873e", "a5c94c78a0d2f0e7", "39412e2877b60728", "a1265ef3afc9a62c",
  "bcc2770c6a2506c5", "3ab66dd5dce1ce12", "e65499d04a675b37", "7d8f523481bfd216",
  "0f6f64fcec15f389", "74efbe618b5b13c8", "acdc82b714273e1d", "dd40bfe003199d17",
  "37e99257e7e061f8", "fa52626904775aaa", "8bbbf63a463d56f9", "f0013f1543a26e64",
  "a8307e9f879ec898", "cc4c27a4150177cc", "1b432f2cca1d3348", "de1d1f8f9f6fa013",
  "606602a047a7ddd6", "d237ab64cc1cb2c7", "9b938e7225fcd1d3", "ec4e03708e0ff476",
  "feb2fbda3d03c12d", "ae0bced2ee43889a", "22cb8923ebfb4f43", "69360d013cf7396d",
  "855e3602d2d4e022", "073805bad01f784c", "33e17a133852f546", "df4874058ac7b638",
  "ba92b29c678aa14a", "0ce89fc76cfaadcd", "5f9d4e0908339e34", "f1afe9291f5923b9",
  "6e3480f60f4a265f", "eebf3a2ab29b841c", "e21938a88f91b4ad", "57dfeff845c6d3c3",
  "2f006b0bf62caaf2", "62f479ef6f75ee78", "11a55ad41c8916a9", "f229d29084fed453",
  "42f1c27b16b000e6", "2b1f76749823c074", "4b76eca3c2745360", "8c98f463b91691bd",
  "14bcc93cf1ade66a", "8885213e6d458397", "8e177df0274d4711", "b49b73b5503f2951",
  "10168168c3f96b6b", "0e3d963b63cab0ae", "8dfc4b5655a1db14", "f789f1356e14de5c",
  "683e68af4e51dac1", "c9a84f9d8d4b0fd9", "3691e03f52a0f9d1", "5ed86e46e1878e80",
  "3c711a0e99d07150", "5a0865b20c4e9310", "56fbfc1fe4f0682e", "ea8d5de3105edf9b",
  "71abfdb12379187a", "2eb99de1bee77b9c", "21ecc0ea33cf4523", "59a4d7521805c7a1",
  "3896f5eb56ae7c72", "aa638f3db18f75dc", "9f39358dabe9808e", "b7defa91c00b72ac",
  "6b5541fd62492d92", "6dc6dee8f92e4d5b", "353f57abc4beea7e", "735769d6da5690ce",
  "0a234aa642391484", "f6f9508028f80d9d", "b8e319a27ab3f215", "31ad9c1151341a4d",
  "773c22a57bef5805", "45c7561a07968633", "f913da9e249dbe36", "da652d9b78a64c68",
  "4c27a97f3bc334ef", "76621220e66b17f4", "967743899acd7d0b", "f3ee5bcae0ed6782",
  "409f753600c879fc", "06d09a39b5926db6", "6f83aeb0317ac588", "01e6ca4a86381f21",
  "66ff3462d19f3025", "72207c24ddfd3bfb", "4af6b6d3e2ece2eb", "9c994dbec7ea08de",
  "49ace597b09a8bc4", "b38c4766cf0797ba", "131b9373c57c2a75", "b1822cce61931e58",
  "9d7555b909ba1c0c", "127fafdd937d11d2", "29da3badc66d92e4", "a2c1d57154c2ecbc",
  "58c5134d82f6fe24", "1c3ae3515b62274f", "e907c82e01cb8126", "f8ed091913e37fcb",
  "3249d8f9c80046c9", "80cf9bede388fb63", "1881539a116cf19e", "5103f3f76bd52457",
  "15b7e6f5ae47f7a8", "dbd7c6ded47e9ccf", "44e55c410228bb1a", "b647d4255edb4e99",
  "5d11882bb8aafc30", "f5098bbb29d3212a", "8fb5ea14e90296b3", "677b942157dd025a",
  "fb58e7c0a390acb5", "89d3674c83bd4a01", "9e2da4df4bf3b93b", "fcc41e328cab4829",
  "03f38c96ba582c52", "cad1bdbd7fd85db2", "bbb442c16082ae83", "b95fe86ba5da9ab0",
  "b22e04673771a93f", "845358c9493152d8", "be2a488697b4541e", "95a2dc2dd38e6966",
  "c02c11ac923c852b", "2388b1990df2a87b", "7c8008fa1b4f37be", "1f70d0c84d54e503",
  "5490adec7ece57d4", "002b3c27d9063a3a", "7eaea3848030a2bf", "c602326ded2003c0",
  "83a7287d69a94086", "c57a5fcb30f57a8a", "b56844e479ebe779", "a373b40f05dcbce9",
  "d71a786e88570ee2", "879cbacdbde8f6a0", "976ad1bcc164a32f", "ab21e25e9666d78b",
  "901063aae5e5c33c", "9818b34448698d90", "e36487ae3e1e8abb", "afbdf931893bdcb4",
  "6345a0dc5fbbd519", "8628fe269b9465ca", "1e5d01603f9c51ec", "4de44006a15049b7",
  "bf6c70e5f776cbb1", "411218f2ef552bed", "cb0c0708705a36a3", "e74d14754f986044",
  "cd56d9430ea8280e", "c12591d7535f5065", "c83223f1720aef96", "c3a0396f7363a51f",
];

const SBOX_HI = new Uint32Array(1024);
const SBOX_LO = new Uint32Array(1024);
for (let i = 0; i < 1024; i++) {
  const hex = SBOX_HEX[i]!;
  SBOX_HI[i] = parseInt(hex.slice(0, 8), 16);
  SBOX_LO[i] = parseInt(hex.slice(8, 16), 16);
}

/** The three pass multipliers, 5, 7 and 9 -- one per pass, in order. */
const MULTIPLIERS = [u64(0, 5), u64(0, 7), u64(0, 9)];

/** The key-schedule constants, from the reference. */
const KS_A5 = u64(0xa5a5a5a5, 0xa5a5a5a5);
const KS_01 = u64(0x01234567, 0x89abcdef);

/** The initial state, which is the same three words for both variants. */
const INITIAL: readonly (readonly [number, number])[] = [
  [0x01234567, 0x89abcdef],
  [0xfedcba98, 0x76543210],
  [0xf096a5b4, 0xc3b2e187],
];

export interface TigerEngine {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

class Tiger implements TigerEngine {
  private readonly state = INITIAL.map(([hi, lo]) => u64(hi, lo));
  private readonly x = Array.from({ length: 8 }, () => u64());
  private readonly a = u64();
  private readonly b = u64();
  private readonly c = u64();
  private readonly t1 = u64();
  private readonly t2 = u64();
  private readonly t3 = u64();
  private readonly ks = u64();
  private readonly rotateTmp = u64();
  private readonly buffer = new Uint8Array(TIGER_BLOCK_LEN);
  private buffered = 0;
  private length = 0;
  private done = false;

  /**
   * `padByte` is the only difference between Tiger and Tiger2: 0x01 against 0x80.
   *
   * `extraPasses` is the number of passes beyond the specified three, so 0 is Tiger/3 and 1 is
   * Tiger/4. `outputLen` truncates the 24-byte digest, which is what `tiger128,*` and `tiger160,*`
   * are.
   */
  constructor(
    private readonly padByte: number,
    private readonly extraPasses: number,
    private readonly outputLen: number,
  ) {
    if (extraPasses < 0 || !Number.isInteger(extraPasses)) {
      throw new Error(`Tiger's extra pass count must be a non-negative integer; got ${extraPasses}.`);
    }
    if (!TIGER_OUTPUT_LENS.includes(outputLen)) {
      throw new Error(`Tiger produces 16, 20 or 24 bytes; ${outputLen} was requested.`);
    }
  }

  /**
   * One round.
   *
   * `c ^= x`, then `a` loses the XOR of four table entries indexed by c's even bytes and `b` gains the
   * XOR of four indexed by its odd ones, before being multiplied. The byte order of those lookups --
   * T1, T2, T3, T4 against bytes 0, 2, 4, 6 and T4, T3, T2, T1 against 1, 3, 5, 7 -- is the part to
   * check against the paper.
   */
  private round(a: U64, b: U64, c: U64, x: U64, mul: U64): void {
    xor64(c, c, x);

    const b0 = c.lo & 0xff;
    const b1 = (c.lo >>> 8) & 0xff;
    const b2 = (c.lo >>> 16) & 0xff;
    const b3 = (c.lo >>> 24) & 0xff;
    const b4 = c.hi & 0xff;
    const b5 = (c.hi >>> 8) & 0xff;
    const b6 = (c.hi >>> 16) & 0xff;
    const b7 = (c.hi >>> 24) & 0xff;

    set64(
      this.t1,
      SBOX_HI[b0]! ^ SBOX_HI[256 + b2]! ^ SBOX_HI[512 + b4]! ^ SBOX_HI[768 + b6]!,
      SBOX_LO[b0]! ^ SBOX_LO[256 + b2]! ^ SBOX_LO[512 + b4]! ^ SBOX_LO[768 + b6]!,
    );
    sub64(a, a, this.t1);

    set64(
      this.t2,
      SBOX_HI[768 + b1]! ^ SBOX_HI[512 + b3]! ^ SBOX_HI[256 + b5]! ^ SBOX_HI[b7]!,
      SBOX_LO[768 + b1]! ^ SBOX_LO[512 + b3]! ^ SBOX_LO[256 + b5]! ^ SBOX_LO[b7]!,
    );
    add64(b, b, this.t2);
    mul64(b, b, mul);
  }

  /** Eight rounds over the eight message words, rotating the registers each time. */
  private pass(a: U64, b: U64, c: U64, mul: U64): void {
    const x = this.x;
    this.round(a, b, c, x[0]!, mul);
    this.round(b, c, a, x[1]!, mul);
    this.round(c, a, b, x[2]!, mul);
    this.round(a, b, c, x[3]!, mul);
    this.round(b, c, a, x[4]!, mul);
    this.round(c, a, b, x[5]!, mul);
    this.round(a, b, c, x[6]!, mul);
    this.round(b, c, a, x[7]!, mul);
  }

  /**
   * The key schedule, run between passes.
   *
   * Sixteen steps over the eight message words, mixing add, subtract, XOR, complement and two shifts.
   * Written out rather than looped because it is not periodic -- the shifts alternate 19 left and 23
   * right, and the two constants appear once each.
   */
  private keySchedule(): void {
    const x = this.x;
    const tmp = this.t3;
    const scratch = this.ks;

    xor64(tmp, x[7]!, KS_A5);
    sub64(x[0]!, x[0]!, tmp);
    xor64(x[1]!, x[1]!, x[0]!);
    add64(x[2]!, x[2]!, x[1]!);
    not64(scratch, x[1]!);
    shl64(scratch, scratch, 19);
    xor64(tmp, x[2]!, scratch);
    sub64(x[3]!, x[3]!, tmp);
    xor64(x[4]!, x[4]!, x[3]!);
    add64(x[5]!, x[5]!, x[4]!);
    not64(scratch, x[4]!);
    shr64(scratch, scratch, 23);
    xor64(tmp, x[5]!, scratch);
    sub64(x[6]!, x[6]!, tmp);
    xor64(x[7]!, x[7]!, x[6]!);
    add64(x[0]!, x[0]!, x[7]!);
    not64(scratch, x[7]!);
    shl64(scratch, scratch, 19);
    xor64(tmp, x[0]!, scratch);
    sub64(x[1]!, x[1]!, tmp);
    xor64(x[2]!, x[2]!, x[1]!);
    add64(x[3]!, x[3]!, x[2]!);
    not64(scratch, x[2]!);
    shr64(scratch, scratch, 23);
    xor64(tmp, x[3]!, scratch);
    sub64(x[4]!, x[4]!, tmp);
    xor64(x[5]!, x[5]!, x[4]!);
    add64(x[6]!, x[6]!, x[5]!);
    xor64(tmp, x[6]!, KS_01);
    sub64(x[7]!, x[7]!, tmp);
  }

  private processBlock(bytes: Uint8Array, at: number): void {
    for (let i = 0; i < 8; i++) copy64(this.x[i]!, readU64LE(bytes, at + i * 8));

    const { a, b, c, state } = this;
    copy64(a, state[0]!);
    copy64(b, state[1]!);
    copy64(c, state[2]!);

    // Three passes with rotating registers and multipliers 5, 7, 9.
    this.pass(a, b, c, MULTIPLIERS[0]!);
    this.keySchedule();
    this.pass(c, a, b, MULTIPLIERS[1]!);
    this.keySchedule();
    this.pass(b, c, a, MULTIPLIERS[2]!);

    /**
     * Any pass beyond the third: key schedule, one pass at multiplier 9, then rotate the registers.
     *
     * The rotation is `a <- c, c <- b, b <- a`, and it is done by swapping *values* rather than
     * rebinding names because the three registers are long-lived objects here. Same effect, and the
     * feedforward below then reads whatever the last rotation left in place -- which is what the
     * reference implementation does and what `tiger192,4` depends on.
     */
    for (let extra = 0; extra < this.extraPasses; extra++) {
      this.keySchedule();
      this.pass(a, b, c, MULTIPLIERS[2]!);
      copy64(this.rotateTmp, a);
      copy64(a, c);
      copy64(c, b);
      copy64(b, this.rotateTmp);
    }

    // Feedforward: XOR, subtract, add -- one of each, which is deliberate.
    xor64(state[0]!, a, state[0]!);
    sub64(state[1]!, b, state[1]!);
    add64(state[2]!, c, state[2]!);
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("Tiger: update after digest");
    this.length += chunk.length;

    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(TIGER_BLOCK_LEN - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === TIGER_BLOCK_LEN) {
        this.processBlock(this.buffer, 0);
        this.buffered = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("Tiger: digest called twice");
    this.done = true;

    // Pad: the variant's byte, zeros, then the bit length as a little-endian 64-bit value.
    let index = this.buffered;
    this.buffer[index++] = this.padByte;
    if (index > 56) {
      this.buffer.fill(0, index);
      this.processBlock(this.buffer, 0);
      index = 0;
    }
    this.buffer.fill(0, index, 56);

    // Length in bits. Done in floating point because a byte count can exceed 2^29 and `<< 3` cannot.
    const bits = u64(
      Math.floor(this.length / 0x2000_0000) >>> 0,
      ((this.length % 0x2000_0000) * 8) >>> 0,
    );
    writeU64LE(this.buffer, 56, bits);
    this.processBlock(this.buffer, 0);

    const full = new Uint8Array(TIGER_OUTPUT_LEN);
    for (let i = 0; i < 3; i++) writeU64LE(full, i * 8, this.state[i]!);
    // 128- and 160-bit Tiger are literal truncations of the 192-bit digest.
    return this.outputLen === TIGER_OUTPUT_LEN ? full : full.subarray(0, this.outputLen);
  }
}

/**
 * Tiger, with the original 0x01 padding byte.
 *
 * `passes` is the total number of passes -- 3 is the paper's Tiger, 4 is PHP's `tiger*,4` -- and
 * `outputLen` truncates.
 */
export function createTiger(passes = 3, outputLen = TIGER_OUTPUT_LEN): TigerEngine {
  if (passes < 3) throw new Error(`Tiger runs at least three passes; ${passes} was requested.`);
  return new Tiger(0x01, passes - 3, outputLen);
}

/** Tiger2, which differs only in padding with 0x80 as every other hash of its era did. */
export function createTiger2(passes = 3, outputLen = TIGER_OUTPUT_LEN): TigerEngine {
  if (passes < 3) throw new Error(`Tiger runs at least three passes; ${passes} was requested.`);
  return new Tiger(0x80, passes - 3, outputLen);
}

export function tiger(
  data: Uint8Array,
  passes = 3,
  outputLen = TIGER_OUTPUT_LEN,
): Uint8Array {
  const h = createTiger(passes, outputLen);
  h.update(data);
  return h.digest();
}

export function tiger2(
  data: Uint8Array,
  passes = 3,
  outputLen = TIGER_OUTPUT_LEN,
): Uint8Array {
  const h = createTiger2(passes, outputLen);
  h.update(data);
  return h.digest();
}

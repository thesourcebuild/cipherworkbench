/**
 * CityHash's own self-test values for its two CRC-accelerated variants, from `city-test.cc`'s
 * `testdata[kTestSize][16]` table -- columns 7 to 10 for the 128-bit forms and 11 to 14 for the
 * 256-bit one.
 *
 * The other columns are the plain CityHash variants and are already asserted by
 * `tests/algos-nonchash.test.ts`, which also builds the 1 MB pseudorandom buffer these cases index
 * into. The driver is CityHash's two-loop one: 299 cases at `(offset = i * i, len = i)` then one at
 * `(0, kDataSize)` -- *not* FarmHash's three-loop 362, which is a different suite.
 *
 * Stored as hex strings rather than numbers on purpose: these are 64-bit values and a JSON round trip
 * through a double silently truncates them. That happened once while extracting this table, and the
 * symptom was every expected value ending in a run of zeros.
 */
export interface CityCrcCase {
  /** [low, high] of CityHashCrc128. */
  readonly crc128: readonly [string, string];
  /** [low, high] of CityHashCrc128WithSeed under the reference's kSeed128. */
  readonly crc128Seed: readonly [string, string];
  /** CityHashCrc256's four words. */
  readonly crc256: readonly [string, string, string, string];
}

export const CITY_CRC_CASES: readonly CityCrcCase[] = [
  {
    crc128: ["3df09dfc64c09a2b", "3cb540c392e51e29"],
    crc128Seed: ["6b56343feac0663", "5b7bc50fd8e8ad92"],
    crc256: ["95162f24e6a5f930", "6808bdf4f1eb06e0", "b3b1f3a67b624d82", "c9a62f12bd4cd80b"],
  },
  {
    crc128: ["c3cdc41e1df33513", "2c138ff2596d42f6"],
    crc128Seed: ["f58e9082aed3055f", "162e192b2957163d"],
    crc256: ["fb99e85e0d16f90c", "608462c15bdf27e8", "e7d2c5c943572b62", "1baaa9327642798c"],
  },
  {
    crc128: ["3149ba1dac77270d", "70e2e076e30703c"],
    crc128Seed: ["59bcc9659bc5296", "9ecbc8132ae2f1d7"],
    crc256: ["a01d30789bad7cf2", "ae03fe371981a0e0", "127e3883b8788934", "d0ac3d4c0a6fca32"],
  },
  {
    crc128: ["2193fb7620cbf23b", "8b6a8ff06cda8302"],
    crc128Seed: ["1a44469afd3e091f", "8b0449376612506"],
    crc256: ["e9d9d41c32ad91d1", "b44ab09f58e3c608", "19e9175f9fcf784", "839b3c9581b4a480"],
  },
  {
    crc128: ["4d09e42f09cc3495", "666236631b9f253b"],
    crc128Seed: ["d28b3763cd02b6a3", "43b249e57c4d0c1b"],
    crc256: ["3887101c8adea101", "8a9355d4efc91df0", "3e610944cc9fecfd", "5bf9eb60b08ac0ce"],
  },
  {
    crc128: ["dc07df53b949c6b", "d2b11b2081aeb002"],
    crc128Seed: ["d212b02c1b13f772", "c0bed297b4be1912"],
    crc256: ["682d3d2ad304e4af", "40e9112a655437a1", "268b09f7ee09843f", "6b9698d43859ca47"],
  },
  {
    crc128: ["d183dcda5f73edfa", "3a93cbf40f30128c"],
    crc128Seed: ["1a92544d0b41dbda", "aec2c4bee81975e1"],
    crc256: ["5f91814d1126ba4b", "f8ac57eee87fcf1f", "c55c644a5d0023cd", "adb761e827825ff2"],
  },
  {
    crc128: ["b140a02ef5c97712", "b7d00ef065b51b33"],
    crc128Seed: ["635121d532897d98", "532daf21b312a6d6"],
    crc256: ["c0b09b75d943910", "8c84dfb5ef2a8e96", "e5c06034b0353433", "3170faf1c33a45dd"],
  },
  {
    crc128: ["26b6689960ccf81d", "55f23b27bb9efd94"],
    crc128Seed: ["3a17f6166dd765db", "c891a8a62931e782"],
    crc256: ["23852dc37ddd2607", "8b7f1b1ec897829e", "d1d69452a54eed8a", "56431f2bd766ec24"],
  },
  {
    crc128: ["98ec31113e5e35d2", "5e4aeb853f1b9aa7"],
    crc128Seed: ["bcf5c8fe4465b7c8", "b1ea3a8243996f15"],
    crc256: ["cabbccedb6407571", "d1e40a84c445ec3a", "33302aa908cf4039", "9f15f79211b5cdf8"],
  },
  {
    crc128: ["71fec0f972248915", "2170ec2061f24574"],
    crc128Seed: ["9eb346b6caa36e82", "2908f0fdbca48e73"],
    crc256: ["8101c99f07c64abb", "b9f4b02b1b6a96a7", "583a2b10cd222f88", "199dae4cf9db24c"],
  },
  {
    crc128: ["df01a322c43a6200", "298b65a1714b5a7e"],
    crc128Seed: ["933b83f0aedf23c", "157bcb44d63f765a"],
    crc256: ["d6e9fc7a272d8b51", "3ee5073ef1a9b777", "63149e31fac02c59", "2f7979ff636ba1d8"],
  },
  {
    crc128: ["d93251758985ee6c", "32a9e9f82ba2a932"],
    crc128Seed: ["3822aacaa95f3329", "db349b2f90a490d8"],
    crc256: ["8d49194a894a19ca", "79a78b06e42738e6", "7e0f1eda3d390c66", "1c291d7e641100a5"],
  },
  {
    crc128: ["77a4ccacd131d9ee", "e1d08eeb2f0e29aa"],
    crc128Seed: ["70b9e3051383fa45", "582d0120425caba"],
    crc256: ["a740eef1846e4564", "572dddb74ac3ae00", "fdb5ca9579163bbd", "a649b9b799c615d2"],
  },
  {
    crc128: ["a154296d11362d06", "d0f0bf1f1cb02fc1"],
    crc128Seed: ["ccb87e09309f90d1", "b24a8e4881911101"],
    crc256: ["1a481b4528559f58", "bf837a3150896995", "4989ef6b941a3757", "2e725ab72d0b2948"],
  },
  {
    crc128: ["3bab18b164396783", "47e385ff9d4c06f"],
    crc128Seed: ["18062081bf558df", "63416eb68f104a36"],
    crc256: ["4abda1560c47ac80", "1ea0e63dc6587aee", "33ec79d92ebc1de", "94f9dccef771e048"],
  },
  {
    crc128: ["ac059617f5906673", "94d50d3dcd3069a7"],
    crc128Seed: ["2b26c3b92dea0f0", "99b7374cc78fc3fb"],
    crc256: ["1a8e3c73cdd40ee8", "cbb5fca06747f45b", "ceec44238b291841", "28bf35cce9c90a25"],
  },
  {
    crc128: ["a4375590b8ae7c82", "168fd42f9ecae4ff"],
    crc128Seed: ["23bbde43de2cb214", "a8c333112a243c8c"],
    crc256: ["10ac012e8c518b49", "64a44605d8b29458", "a67e701d2a679075", "3a3a20f43ec92303"],
  },
  {
    crc128: ["6b54fc38d6a84108", "32f4212a47a4665"],
    crc128Seed: ["6b5a9a8f64ee1da6", "9f74e86c6da69421"],
    crc256: ["946dd0cb30c1a08e", "fdf376956907eaaa", "a59074c6eec03028", "b1a3abcf283f34ac"],
  },
  {
    crc128: ["f86af0b40dcce7b", "8d3c15d613394d3c"],
    crc128Seed: ["491e400491cd4ece", "7c19d3530ea3547f"],
    crc256: ["1362963a1dc32af9", "fb9bc11762e1385c", "9e164ef1f5376083", "6c15819b5e828a7e"],
  },
  {
    crc128: ["7ebc034235bc122f", "d9a7783d4edd8049"],
    crc128Seed: ["5f8b04a15ae42361", "fc193363336453dd"],
    crc256: ["9b6c50224ef8c4f8", "ba225c7942d16c3f", "6f6d55226a73c412", "abca061fe072152a"],
  },
  {
    crc128: ["9e4ea5a4941e097d", "547e048d5a9daaba"],
    crc128Seed: ["eb6ecbb0b831d185", "e0168df5fad0c670"],
    crc256: ["afa9705f98c2c96a", "749436f48137a96b", "759c041fc21df486", "b23bf400107aa2ec"],
  },
  {
    crc128: ["ce2744521944f14c", "104f8032f99dc152"],
    crc128Seed: ["4e7f425bfac67ca7", "9461b911a1c6d589"],
    crc256: ["5e5ecc726db8b60d", "cce68b0586083b51", "8a7f8e54a9cba0fc", "42f010181d16f049"],
  },
  {
    crc128: ["4ee107042e512374", "1e2c8c0d16097e13"],
    crc128Seed: ["210c7500995aa0e6", "6c13190557106457"],
    crc256: ["a99b31c96777f381", "8312ae8301d386c0", "ed5042b2a4fa96a3", "d71d1bb23907fe97"],
  },
  {
    crc128: ["6ee1f817ce0b7aee", "e9dcb3507f0596ca"],
    crc128Seed: ["6bc63c666b5100e2", "e0b056f1821752af"],
    crc256: ["8ea1114e60292678", "904b80b46becc77", "46cd9bb6e9dff52f", "4c91e3b698355540"],
  },
  {
    crc128: ["d367ff54952a958", "cdad930657371147"],
    crc128Seed: ["aa24dc2a9573d5fe", "eb136daa89da5110"],
    crc256: ["de623005f6d46057", "b50c0c92b95e9b7f", "a8aa54050b81c978", "573fb5c7895af9b5"],
  },
  {
    crc128: ["50d8a70e7a8d8f56", "256d150ae75dab76"],
    crc128Seed: ["e81f4c4a1989036a", "d0f8db365f9d7e00"],
    crc256: ["753d686677b14522", "9f76e0cb6f2d0a66", "ab14f95988ec0d39", "97621d9da9c9812f"],
  },
  {
    crc128: ["a90f761e8db1543a", "c339e23c09703cd8"],
    crc128Seed: ["f0c6624c4b098fd3", "1bae2053e41fa4d9"],
    crc256: ["3589e273c22ba059", "63798246e5911a0b", "18e710ec268fc5dc", "714a122de1d074f3"],
  },
  {
    crc128: ["23dacb811652ad4f", "c982da480e0d4c7d"],
    crc128Seed: ["3a9c8ed5a399d0a9", "951b8d084691d4e4"],
    crc256: ["d9f87b4988cff2f7", "217a191d986aa3bc", "6ad23c56b480350", "dd78673938ceb2e7"],
  },
  {
    crc128: ["c801faaa0a2e331f", "491dbc58279c7f88"],
    crc128Seed: ["9c0178848321c97a", "9d934f814f4d6a3c"],
    crc256: ["606a3e4fc8763192", "bc15cb36a677ee84", "52d5904157e1fe71", "1588dd8b1145b79b"],
  },
  {
    crc128: ["68dd76db9d64eca7", "36297682b64b67"],
    crc128Seed: ["42b192d71f414b7a", "79692cef44fa0206"],
    crc256: ["f0979252f4776d07", "4b87cd4f1c9bbf52", "51b84bbc6312c710", "150720fbf85428a7"],
  },
  {
    crc128: ["b2e25964cd409117", "a010599d6287c412"],
    crc128Seed: ["fa5d6461e768dda2", "cb3ce74e8ec4f906"],
    crc256: ["6120abfd541a2610", "aa88b148cc95794d", "2686ca35df6590e3", "c6b02d18616ce94d"],
  },
  {
    crc128: ["9a8c431f500ef06e", "d848581a580b6c12"],
    crc128Seed: ["fecfe11e13a2bdb4", "6c4fa0273d7db08c"],
    crc256: ["482f43bf5ae59fcb", "f651fbca105d79e6", "f09f78695d865817", "7a99d0092085cf47"],
  },
  {
    crc128: ["7870765b470b2c5d", "78a9103ff960d82"],
    crc128Seed: ["7bb50ffc9fac74b3", "477e70ab2b347db2"],
    crc256: ["a625238bdf7c07cf", "1128d515174809f5", "b0f1647e82f45873", "17792d1c4f222c39"],
  },
  {
    crc128: ["ea349dbc16c2e441", "38a7455b6a877547"],
    crc128Seed: ["5f97b9750e365411", "e8cde7f93af49a3"],
    crc256: ["ba101925ec1f7e26", "d5e84cab8192c71e", "e256427726fdd633", "a4f38e2c6116890d"],
  },
  {
    crc128: ["5d9dde77353b1a6d", "11f58c54581fa8b1"],
    crc128Seed: ["da90fa7c28c37478", "5e9a2eafc670a88a"],
    crc256: ["e35e1bc172e011ef", "bf9255a4450ae7fe", "55f85194e26bc55f", "4f327873e14d0e54"],
  },
  {
    crc128: ["bf41e5376b9f0eec", "2252d21eb7e1c0e9"],
    crc128Seed: ["f4b70a971855e732", "40c7695aa3662afd"],
    crc256: ["770fe19e16ab73bb", "d603ebda6393d749", "e58c62439aa50dbd", "96d51e5a02d2d7cf"],
  },
  {
    crc128: ["a1924cbf0b5f9222", "7f4872369c2b4258"],
    crc128Seed: ["cd6da30530f3ea89", "b7f8b9a704e6cea1"],
    crc256: ["fa06ff40433fd535", "fb1c36fe8f0737f1", "bb7050561171f80", "b1bc23235935d897"],
  },
  {
    crc128: ["f7dbc8433c89b274", "2f5f70581c9b7d32"],
    crc128Seed: ["39bf5e5fec82dcca", "8ade56388901a619"],
    crc256: ["c1c6a725caab3ea9", "c1c7906c2f80b898", "9c3871a04cc884e6", "df01813cbbdf217f"],
  },
  {
    crc128: ["8ffe870ef4adc087", "65bea2be41f55b54"],
    crc128Seed: ["82f3503f636aef1", "5f78a282378b6bb0"],
    crc256: ["7bf2422c0beceddb", "9d238d4780114bd", "7ad198311906597f", "ec8f892c0422aca3"],
  },
  {
    crc128: ["3df9b04434771542", "feddce785ccb661f"],
    crc128Seed: ["a644aff716928297", "dd46aee73824b4ed"],
    crc256: ["bf8d71879da29b02", "fc82dccbfc8022a0", "31bfcd0d9f48d1d3", "c64ee24d0e7b5f8b"],
  },
  {
    crc128: ["7d2c38a926dc1b88", "5245b9eb4cd6791d"],
    crc128Seed: ["fb53ab03b9ad0855", "3664026c8fc669d7"],
    crc256: ["45024d5080bc196", "b236ebec2cc2740", "27231ad0e3443be4", "145780b63f809250"],
  },
  {
    crc128: ["864b1b28ec16ea86", "6a78a5a4039ec2b9"],
    crc128Seed: ["8e959533e35a766", "347b7c22b75ae65f"],
    crc256: ["5005892bb61e647c", "fe646519b4a1894d", "cd801026f74a8a53", "8713463e9a1ab9ce"],
  },
  {
    crc128: ["2e8c49d7c7aaa527", "5e2328fc8701db7c"],
    crc128Seed: ["89ef1afca81f7de8", "b1857db11985d296"],
    crc256: ["17763d695f616115", "b8f7bf1fcdc8322c", "cf0c61938ab07a27", "1122d3e6edb4e866"],
  },
  {
    crc128: ["3b69edadf357432b", "3a2e311c121e6bf2"],
    crc128Seed: ["380fad1e288d57e5", "bf7c7e8ef0e3b83a"],
    crc256: ["92966d5f4356ae9b", "2a03fc66c4d6c036", "2516d8bddb0d5259", "b3ffe9737ff5090"],
  },
  {
    crc128: ["cd7a46850b95e901", "c57f7d060dda246f"],
    crc128Seed: ["6b9406ead64079bf", "11b28e20a573b7bd"],
    crc256: ["2d6db356e9369ace", "dc0afe10fba193", "5cdb10885dbbfce", "5c700e205782e35a"],
  },
  {
    crc128: ["8c1df927a930af59", "a462f4423c9e384e"],
    crc128Seed: ["236542255b2ad8d9", "595d201a2c19d5bc"],
    crc256: ["22c87d4604a67f3", "585a06eb4bc44c4f", "b4175a7ac7eabcd8", "a457d3eeba14ab8c"],
  },
  {
    crc128: ["9498fefb890287ce", "ae68c2be5b1a69a6"],
    crc128Seed: ["6189dfba34ed656c", "91658f95836e5206"],
    crc256: ["c0bb4fff32aecd4d", "94125f505a50eef9", "6ac406e7cfbce5bb", "344a4b1dcdb7f5d8"],
  },
  {
    crc128: ["7a0b6dbab9a14e69", "c6d0a9d6b0e31ac4"],
    crc128Seed: ["a674d85812c7cf6", "63538c0351049940"],
    crc256: ["9710e5f0bc93d1d", "c2bea5bd7c54ddd4", "48739af2bed0d32d", "ba2c4e09e21fba85"],
  },
  {
    crc128: ["843b58463c8df0ae", "74b258324e916045"],
    crc128Seed: ["bdd7353230eb2b38", "fad31fced7abade5"],
    crc256: ["2436aeafb0046f85", "65bc9af9e5e33161", "92733b1b3ae90628", "f48143eaf78a7a89"],
  },
  {
    crc128: ["cc76f429ea7a12bb", "5f30eaf2bb14870a"],
    crc128Seed: ["434e824cb3e0cd11", "431a4d382e39d16e"],
    crc256: ["9e51f913c4773a8", "32ab1925823d0add", "99c61b54c1d8f69d", "38cfb80f02b43b1f"],
  },
  {
    crc128: ["328063229db22884", "67e9c95f8ba96028"],
    crc128Seed: ["7c6bf01c60436075", "fa55161e7d9030b2"],
    crc256: ["dadbc2f0dab91681", "da39d7a4934ca11", "162e845d24c1b45c", "eb5b9dcd8c6ed31b"],
  },
  {
    crc128: ["f72c26e624407e66", "a0eb541bdbc6d409"],
    crc128Seed: ["c3f40a2f40b3b213", "6a784de68794492d"],
    crc256: ["10a38a23dbef7937", "6a5560f853252278", "c3387bbf3c7b82ba", "fbee7c12eb072805"],
  },
  {
    crc128: ["405f66cf8cae1a32", "d7261740d8f18ce6"],
    crc128Seed: ["fea3af64a413d0b2", "d64d1810e83520fe"],
    crc256: ["e1334a00a580c6e8", "454049e1b52c15f", "8895d823d9778247", "efa7f2e88b826618"],
  },
  {
    crc128: ["d4eccebe9393ee8a", "2eb7867c2318cc59"],
    crc128Seed: ["1ce621fd700fe396", "686450d7a346878a"],
    crc256: ["75a5f37579f8b4cb", "500cc16eb6541dc7", "b7b02317b539d9a6", "3519ddff5bc20a29"],
  },
  {
    crc128: ["7a61d8f552a53442", "821d1d8d8cfacf35"],
    crc128Seed: ["7cc06361b86d0559", "119b617a8c2be199"],
    crc256: ["2996487da6721759", "61a901376070b91d", "d88dee12ae9c9b3c", "5665491be1fa53a7"],
  },
  {
    crc128: ["2247a4b2058d1c50", "1b3fa184b1d7bcc0"],
    crc128Seed: ["deb85613995c06ed", "cbe1d957485a3ccd"],
    crc256: ["dfe241f8f33c96b6", "6597eb05019c2109", "da344b2a63a219cf", "79b8e3887612378a"],
  },
  {
    crc128: ["e8b9ee96efa2d0e", "90122905c4ab5358"],
    crc128Seed: ["84f80c832d71979c", "229310f3ffbbf4c6"],
    crc256: ["cc9eb42100cd63a7", "7a283f2f3da7b9f", "359b061d314e7a72", "d0d959720028862"],
  },
  {
    crc128: ["2e091b85660f1298", "bfe37fae1cdd64c9"],
    crc128Seed: ["8dddfbab930f6494", "2ccf4b08f5d417a"],
    crc256: ["365c2ee85582fe6", "dee027bcd36db62a", "b150994d3c7e5838", "fdfd1a0e692e436d"],
  },
  {
    crc128: ["7a9d77781ac53509", "4489c3ccfda3b39c"],
    crc128Seed: ["fa722d4f243b4964", "25f15800bffdd122"],
    crc256: ["ed85e4157fbd3297", "aab1967227d59efd", "2199631212eb3839", "3e4c19359aae1cc2"],
  },
  {
    crc128: ["9deefbcfa4cab1f1", "b58f5943cd2492ba"],
    crc128Seed: ["a96dcc4d1f4782a7", "102b62a82309dde5"],
    crc256: ["35fe52684763b338", "afe2616651eaad1f", "43e38715bdfa05e7", "83c9ba83b5ec4a40"],
  },
  {
    crc128: ["cfc6d7adda35797", "14c7d1f32332cf03"],
    crc128Seed: ["2d553ffbff3be99d", "c91c4ee0cb563182"],
    crc256: ["9aa5e507f49136f0", "760c5dd1a82c4888", "beea7e974a1cfb5c", "640b247774fe4bf7"],
  },
  {
    crc128: ["bce905900c1ec6ea", "c30f304f4045487d"],
    crc128Seed: ["a5c550166b3a142b", "2f482b4e35327287"],
    crc256: ["15b21ddddf355438", "496471fa3006bab", "2a8fd458d06c1a32", "db91e8ae812f0b8d"],
  },
  {
    crc128: ["910b610de7a967bf", "801bc862120f6bf5"],
    crc128Seed: ["9653efeed5897681", "f5367ff83e9ebbb3"],
    crc256: ["cf56d489afd1b0bf", "c7c793715cae3de8", "631f91d64abae47c", "5f1f42fb14a444a2"],
  },
  {
    crc128: ["d1d44fe99451ef72", "ec951ba8e51e3545"],
    crc128Seed: ["c0ca86b360746e96", "aa679cc066a8040b"],
    crc256: ["51065861ece6ffc1", "76777368a2997e11", "87f278f46731100c", "bbaa4140bdba4527"],
  },
  {
    crc128: ["d3e86ac4f5eccfa4", "e5399df2b106ca1"],
    crc128Seed: ["814aadfacd217f1d", "2754e3def1c405a9"],
    crc256: ["99290323b9f06e74", "a9782e043f271461", "13c8b3b8c275a860", "6038d620e581e9e7"],
  },
  {
    crc128: ["69afbc800606d0fb", "6104b97a9db12df7"],
    crc128Seed: ["fcc09198bb90bf9f", "c5e077e41a65ba91"],
    crc256: ["db261835ee8aa08e", "db0ee662e5796dc9", "fc1880ecec499e5f", "648866fbe1502034"],
  },
  {
    crc128: ["909ae019d761d019", "368bf4aab1b86ef9"],
    crc128Seed: ["308bd616d5460239", "4fd33269f76783ea"],
    crc256: ["7d53b37c19713eab", "6bba6eabda58a897", "91abb50efc116047", "4e902f347e0e0e35"],
  },
  {
    crc128: ["ef79f28d874b9e2d", "b512089e8e63b76c"],
    crc128Seed: ["24dc06833bf193a9", "3c23308ba8e99d7e"],
    crc256: ["5ceff7b85cacefb7", "ef390338898cd73", "b12967d7d2254f54", "de874cbd8aef7b75"],
  },
  {
    crc128: ["8184bab36bb79df0", "c81929ce8655b940"],
    crc128Seed: ["301b11bf8a4d8ce8", "73126fd45ab75de9"],
    crc256: ["4bd6f76e4888229a", "9aae355b54a756d5", "ca3de9726f6e99d5", "83f80cac5bc36852"],
  },
  {
    crc128: ["bc61414f9802ecaf", "8edd1e7a50562924"],
    crc128Seed: ["48f4ab74a35e95f2", "cc1afcfd99a180e7"],
    crc256: ["517dd5e3acf66110", "7dd3ad9e8978b30d", "1f6d5dfc70de812b", "947daaba6441aaf3"],
  },
  {
    crc128: ["d45e44c263e95c38", "df61db53923ae3b1"],
    crc128Seed: ["f2bc948cc4fc027c", "8a8000c6066772a3"],
    crc256: ["9fd93c942d31fa17", "d7651ecebe09cbd3", "68682cefb6a6f165", "541eb99a2dcee40e"],
  },
  {
    crc128: ["30e888af70df1e56", "4bee54bd47274f69"],
    crc128Seed: ["178b4059e1a0afe5", "6e2c96b7f58e5178"],
    crc256: ["bb429d3b9275e9bc", "c198013f09cafdc6", "ec0a6ee4fb5de348", "744e1e8ed2eb1eb0"],
  },
  {
    crc128: ["8b1d7bb4903c105f", "cfb1c322b73891d4"],
    crc128Seed: ["5f3b792b22f07297", "fd64061f8be86811"],
    crc256: ["1d2db712921cfc2b", "cd1b2b2f2cee18ae", "6b6f8790dc7feb09", "46c179efa3f0f518"],
  },
  {
    crc128: ["852c9499156a8f3", "3a180a6abfb79016"],
    crc128Seed: ["9fc3c4764037c3c9", "2890c42fc0d972cf"],
    crc256: ["1f92231d4e537651", "fab8bb07aa54b7b9", "e05d2d771c485ed4", "d50b34bf808ca731"],
  },
  {
    crc128: ["939f31de14dcdc7b", "a68fdf4379df068"],
    crc128Seed: ["f169e1f0b835279d", "7498e432f9619b27"],
    crc256: ["1aa2a1f11088e785", "d6ad72f45729de78", "9a63814157c80267", "55538e35c648e435"],
  },
  {
    crc128: ["11b87fb1b900cc39", "e33e59b90dd815b1"],
    crc128Seed: ["aa6cb5c4bafae741", "739699951ca8c713"],
    crc256: ["2b4389a967310077", "1d5382568a31c2c9", "55d1e787fbe68991", "277c254bc31301e7"],
  },
  {
    crc128: ["a64760e4041447d0", "e3eac49f3e0c5109"],
    crc128Seed: ["dd86c4d4cb6258e2", "efa9857afd046c7f"],
    crc256: ["fab793dae8246f16", "c9e3b121b31d094c", "a2a0f55858465226", "dba6f0ff39436344"],
  },
  {
    crc128: ["501f3e9b18861e44", "465201170074e7d8"],
    crc128Seed: ["96d5c91970f2cb12", "40fd28c43506c95d"],
    crc256: ["e86c4b07802aaff3", "f317d14112372a70", "641b13e587711650", "4915421ab1090eaa"],
  },
  {
    crc128: ["154dd79fd2f984b4", "f11171775622c1c3"],
    crc128Seed: ["1fbe30982e78e6f0", "a460a15dcf327e44"],
    crc256: ["f359e0900cc3d582", "7e11070447976d00", "324e6daf276ea4b5", "7aa6e2df0cc94fa2"],
  },
  {
    crc128: ["b7e164979d5ccfc1", "12cb4230d26bf286"],
    crc128Seed: ["f1bf910d44bd84cb", "b32c24c6a40272"],
    crc256: ["11ed12e34c48c039", "b0c2538e51d0a6ac", "4269bb773e1d553a", "e35a9dbabd34867"],
  },
  {
    crc128: ["3ff6c8ac7c36b63a", "48bc8831d849e326"],
    crc128Seed: ["30b078e76b0214e2", "42954e6ad721b920"],
    crc256: ["f9aeb33d164b4472", "7b353b110831dbdc", "16f64c82f44ae17b", "b71244cc164b3b2b"],
  },
  {
    crc128: ["1a57313a32f22dde", "30af46e49850bf8b"],
    crc128Seed: ["aa0fe8d12f808f83", "443e31d70873bb6b"],
    crc256: ["bbeb67c49c9fdc13", "18f1e2a88f59f9d5", "fb1b05038e5def11", "d0450b5ce4c39c52"],
  },
  {
    crc128: ["e9029e6364286587", "ae69f49ecb46726c"],
    crc128Seed: ["18e002679217c405", "bd6d66e85332ae9f"],
    crc256: ["6bf330b1c353dd2a", "74e9f2e71e3a4152", "3f85560b50f6c413", "d33a52a47eaed2b4"],
  },
  {
    crc128: ["3d8c90e27aa2e147", "2ec937ce0aa236b4"],
    crc128Seed: ["89b563996d3a0b78", "39b02413b23c3f08"],
    crc256: ["8d475a2e64faf2d2", "48567f7dca46ecaf", "254cda08d5f87a6d", "ec6ae9f729c47039"],
  },
  {
    crc128: ["4d50c7537562033f", "57dc7625b61dfe89"],
    crc128Seed: ["9723a9f4c08ad93a", "5309596f48ab456b"],
    crc256: ["7e453088019d220f", "8776067ba6ab9714", "67e1d06bd195de39", "74a1a32f8994b918"],
  },
  {
    crc128: ["45504801e0e6066b", "86e6c6d6152a3d04"],
    crc128Seed: ["4f3db1c53eca2952", "d24d69b3e9ef10f3"],
    crc256: ["93a0de2219e66a70", "8932c7115ccb1f8a", "5ef503fdf2841a8c", "38064dd9efa80a41"],
  },
  {
    crc128: ["f13bc2d9c2fe222e", "be4ccec9a6cdccfd"],
    crc128Seed: ["37b2cbdd973a3ac9", "7b3223cd9c9497be"],
    crc256: ["d5904440f376f889", "62b13187699c473c", "4751b89251f26726", "9500d84fa3a61ba8"],
  },
  {
    crc128: ["3752b423073b119a", "377dc5eb7c662bdb"],
    crc128Seed: ["2b9f07f93a6c25b9", "96f24ede2bdc0718"],
    crc256: ["f7699b12c31417bd", "17b366f401c58b2", "bf60188d5f437b37", "484436e56df17f04"],
  },
  {
    crc128: ["ebdbb918eb6d837f", "8fb5f218dd84147c"],
    crc128Seed: ["c77dd1f881df2c54", "62eac298ec226dc3"],
    crc256: ["43eded83c4b60bd0", "9a0a403b5487503b", "25f305d9147f0bda", "3ad417f511bc1e64"],
  },
  {
    crc128: ["f1b9b413df9d79ed", "a7621b6fd02db503"],
    crc128Seed: ["d92f7ba9928a4ffe", "53f56babdcae96a6"],
    crc256: ["5302b89fc48713ab", "d03e3b04dbe7a2f2", "fa74ef8af6d376a7", "103c8cdea1050ef2"],
  },
  {
    crc128: ["a53a6b64b1ac85c9", "d50e7f86ee1b832b"],
    crc128Seed: ["7bab08fdd26ba0a4", "7587743c18fe2475"],
    crc256: ["e3b5d5d490cf5761", "dfc053f7d065edd5", "42ffd8d5fb70129f", "599ca38677cccdc3"],
  },
  {
    crc128: ["dbfaae9642b3205a", "f676a1339402bcb9"],
    crc128Seed: ["f4f12a5b1ac11f29", "7db8bad81249dee4"],
    crc256: ["b26e46f2da95922e", "2aaedd5e12e3c611", "a0e2d9082966074", "c64da8a167add63d"],
  },
  {
    crc128: ["47418a71800334a0", "d10395d8fc64d8a4"],
    crc128Seed: ["8257a30062cb66f", "6786f9b2dc1ff18a"],
    crc256: ["5633f437bb2f180f", "e5a3a405737d22d6", "ca0ff1ef6f7f0b74", "d0ae600684b16df8"],
  },
  {
    crc128: ["caa33cf9b4f6619c", "b2c8648ad49c209f"],
    crc128Seed: ["9e89ece0712db1c0", "101d8274a711a54b"],
    crc256: ["538e79f1e70135cd", "e1f5a76f983c844e", "653c082fd66088fc", "1b9c9b464b654958"],
  },
  {
    crc128: ["941f5023c0c943f9", "dfdeb9564fd66f24"],
    crc128Seed: ["2140cec706b9d406", "7b22429b131e9c72"],
    crc256: ["94215c22eb940f45", "d28b9ed474f7249a", "6f25e88f2fbf9f56", "b6718f9e605b38ac"],
  },
  {
    crc128: ["7e7f61684080106", "837ace9794582976"],
    crc128Seed: ["5ac8ca76a357eb1b", "32b58308625661fb"],
    crc256: ["c09705c4572025d9", "f9187f6af0291303", "1c0edd8ee4b02538", "e6cb105daa0578a"],
  },
  {
    crc128: ["272d8dd74f3006cc", "ec6c2ad1ec03f554"],
    crc128Seed: ["4ad276b249a5d5dd", "549a22a17c0cde12"],
    crc256: ["602119cb824d7cde", "f4d3cef240ef35fa", "e889895e01911bc7", "785a7e5ac20e852b"],
  },
  {
    crc128: ["7b2271a7a3248e22", "3b4f700e5a0ba523"],
    crc128Seed: ["8ebc520c227206fe", "da3f861490f5d291"],
    crc256: ["d08a689f9f3aa60e", "547c1b97a068661f", "4b15a67fa29172f0", "eaf40c085191d80f"],
  },
  {
    crc128: ["3f1229f4d0fd96fb", "33130aa5fa9d43f2"],
    crc128Seed: ["e42693d5b34e63ab", "2f4ef2be67f62104"],
    crc256: ["372e5153516e37b9", "af9ec142ab12cc86", "777920c09345e359", "e7c4a383bef8adc6"],
  },
  {
    crc128: ["7d3e82d5ba29a90d", "d5983cc93a9d126a"],
    crc128Seed: ["37e9dfd950e7b692", "80673be6a7888b87"],
    crc256: ["57f732dc600808bc", "59477199802cc78b", "f824810eb8f2c2de", "c4a3437f05b3b61c"],
  },
  {
    crc128: ["1f3dcdfa513512d6", "4dc7ec07283117e4"],
    crc128Seed: ["4438bae88ae28bf9", "aa7eae72c9244a0d"],
    crc256: ["b9aedc8d3ecc72df", "b75a8eb090a77d62", "6b15677f9cd91507", "51d8282cb3a9ddbf"],
  },
  {
    crc128: ["b3b782ad308f21ed", "4f2676485041dee0"],
    crc128Seed: ["bfe279aed5cb4bc8", "2a62508a467a22ff"],
    crc256: ["e74d29eab742385d", "56b05cd90ecfc293", "c603728ea73f8844", "8638fcd21bc692c4"],
  },
  {
    crc128: ["44d68afda9568f08", "478568ed51ca1d65"],
    crc128Seed: ["679c204ad3d9e766", "b28e788878488dc1"],
    crc256: ["d001a84d3a84fae6", "d376958fe4cb913e", "17435277e36c86f0", "23657b263c347aa6"],
  },
  {
    crc128: ["c3314e362764ddb8", "6481c084ee9ec6b5"],
    crc128Seed: ["ede23fb9a251771", "bd617f2643324590"],
    crc256: ["d2d30c9b95e030f5", "8a517312ffc5795e", "8b1f325033bd535e", "3ee6e867e03f2892"],
  },
  {
    crc128: ["2c6aa706129cc54c", "17a706f59a49f086"],
    crc128Seed: ["c7c1eec455217145", "6adfdc6e07602d42"],
    crc256: ["fb75fca30d848dd2", "5228c9ed14653ed4", "953958910153b1a2", "a430103a24f42a5d"],
  },
  {
    crc128: ["fc3e3c322cd5d89b", "b7e3911dc2bd4ebb"],
    crc128Seed: ["fcd6da5e5fae833a", "51ed3c41f87f9118"],
    crc256: ["f31750cbc19c420a", "186dab1abada1d86", "ca7f88cb894b3cd7", "2859eeb1c373790c"],
  },
  {
    crc128: ["914f1ea2fdcebf5c", "9566453c07cd0601"],
    crc128Seed: ["9841bf66d0462cd", "79140c1c18536aeb"],
    crc256: ["a963b930b05820c2", "6a7d9fa0c8c45153", "64214c40d07cf39b", "7057daf1d806c014"],
  },
  {
    crc128: ["99468a917986162b", "7b31434aac6e0af0"],
    crc128Seed: ["f6915c1562c7d82f", "e4071d82a6dd71db"],
    crc256: ["5f5331f077b5d996", "7b314ba21b747a4f", "5a73cb9521da17f5", "12ed435fae286d86"],
  },
  {
    crc128: ["8799e4740e573c50", "9e739b52d0f341e8"],
    crc128Seed: ["cdfd34ba7d7b03eb", "5061812ce6c88499"],
    crc256: ["612b8d8f2411dc5c", "878bd883d29c7787", "47a846727182bb", "ec4949508c8b3b9a"],
  },
  {
    crc128: ["8063d80ab26f3d6d", "4177b4b9b4f0393f"],
    crc128Seed: ["6de42ba8672b9640", "d0bccdb72c51c18"],
    crc256: ["af3f611b7f22cf12", "3863c41492645755", "928c7a616a8f14f9", "a82c78eb2eadc58b"],
  },
  {
    crc128: ["52c44837aa6dfc77", "15d8d8fccdd6dc5b"],
    crc128Seed: ["345b793ccfa93055", "932160fe802ca975"],
    crc256: ["a624b0dd93fc18cd", "d955b254c2037f1e", "e540533d370a664c", "2ba4ec12514e9d7"],
  },
  {
    crc128: ["c791b313aba3f258", "443c7757a4727bee"],
    crc128Seed: ["e30e4b2372171bdf", "f3db986c4156f3cb"],
    crc256: ["a939aefab97c6e15", "dbeb8acf1d5b0e6c", "1e0eab667a795bba", "80dd539902df4d50"],
  },
  {
    crc128: ["bc241579d8348401", "16dc832804d728f0"],
    crc128Seed: ["e9cc71ae64e3f09e", "bef634bc978bac31"],
    crc256: ["7f64b1fa2a9129e", "71d831bd530ac7f3", "c7ad0a8a6d5be6f1", "82a7d3a815c7aaab"],
  },
  {
    crc128: ["4283001239888836", "f44ca39a6f79db89"],
    crc128Seed: ["ed186122d71bcc9f", "8620017ab5f3ba3b"],
    crc256: ["e787472187f176c", "267e64c4728cf181", "f1ba4b3007c15e30", "8e3a75d5b02ecfc0"],
  },
  {
    crc128: ["374dd4288e0b72e5", "ff8916db706c0df4"],
    crc128Seed: ["cb1a9e85de5e4b8d", "d4d12afb67a27659"],
    crc256: ["feb69095d1ba175a", "e2003aab23a47fad", "8163a3ecab894b49", "46d356674ce041f6"],
  },
  {
    crc128: ["9136456740119815", "4d8ff7733b27eb83"],
    crc128Seed: ["ea3040bc0c717ef8", "7617ab400dfadbc"],
    crc256: ["fb336770c10b17a1", "6123b68b5b31f151", "1e147d5f295eccf2", "9ecbb1333556f977"],
  },
  {
    crc128: ["14cf7f02dab0eee8", "6d01750605e89445"],
    crc128Seed: ["4f1cf4006e613b78", "57c40c4db32bec3b"],
    crc256: ["1fde5a347f4a326e", "cb5a54308adb0e3f", "14994b2ba447a23c", "7067d0abb4257b68"],
  },
  {
    crc128: ["570d62758ddf6397", "5e0204fb68a7b800"],
    crc128Seed: ["4383a9236f8b5a2b", "7bc1a64641d803a4"],
    crc256: ["5434d61285099f7a", "d49449aacdd5dd67", "97855ba0e9a7d75d", "da67328062f3a62f"],
  },
  {
    crc128: ["c738a77a9a55f0e2", "705221addedd81df"],
    crc128Seed: ["fd9bd8d397abcfa3", "8ccf0004aa86b795"],
    crc256: ["2bb5db2280068206", "8c22d29f307a01d", "274a22de02f473c8", "b8791870f4268182"],
  },
  {
    crc128: ["9b82567ab6560796", "891b69462b41c224"],
    crc128Seed: ["8eccc7e4f3af3b51", "381e54c3c8f1c7d0"],
    crc256: ["c80fbc489a558a55", "1ba88e062a663af7", "af7b1ef1c0116303", "bd20e1a5a6b1a0cd"],
  },
  {
    crc128: ["3c13e894365dc6c2", "26fc7bbcda3f0ef"],
    crc128Seed: ["dbb71106cdbfea36", "785239a742c6d26d"],
    crc256: ["f810c415ae05b2f4", "bb9b9e7398526088", "70128f1bf830a32b", "bcc73f82b6410899"],
  },
  {
    crc128: ["6e65ec14a8fb565", "34bff6f2ee5a7f79"],
    crc128Seed: ["2e329a5be2c011b", "73161c93331b14f9"],
    crc256: ["15d13f2408aecf88", "9f5b61b8a4b55b31", "8fe25a43b296dba6", "bdad03b7300f284e"],
  },
  {
    crc128: ["379f76458a3c8957", "79dd080f9843af77"],
    crc128Seed: ["c46f0a7847f60c1d", "af1579c5797703cc"],
    crc256: ["8b7d31f338755c14", "2eff97679512aaa8", "df07d68e075179ed", "c8fa6c7a729e7f1f"],
  },
  {
    crc128: ["1e6f0910c3d25bd8", "ad9e250862102467"],
    crc128Seed: ["1c842a07abab30cd", "cd8124176bac01ac"],
    crc256: ["ea6ebe7a79b67edc", "73f598ac9db26713", "4f4e72d7460b8fc", "365dc4b9fdf13f21"],
  },
  {
    crc128: ["b1cf09b0184a4834", "5c03db48eb6cc159"],
    crc128Seed: ["f18c7fcf34d1df47", "dfb043419ecf1fa9"],
    crc256: ["dcd78d13f9ca658f", "4355d408ffe8e49f", "81eefee908b593b4", "590c213c20e981a3"],
  },
  {
    crc128: ["ceaf1a0d15234f15", "1450a54e45ba9b9"],
    crc128Seed: ["65e9c1fd885aa932", "354d4bc034ba8cbe"],
    crc256: ["8fd4ff484c08fb4b", "bf46749866f69ba0", "cf1c21ede82c9477", "4217548c43da109"],
  },
  {
    crc128: ["85b8e53f22e19507", "bb57137739ca486b"],
    crc128Seed: ["c77f131cca38f761", "c56ac3cf275be121"],
    crc256: ["9ec1a6c9109d2685", "3dad0922e76afdb0", "fd58cbf952958103", "7b04c908e78639a1"],
  },
  {
    crc128: ["adc52dddb76f6e5e", "4aad4e925a962b68"],
    crc128Seed: ["204b79b7f7168e64", "df29ed6671c36952"],
    crc256: ["e02927cac396d210", "5d500e71742b638a", "5c9998af7f27b124", "3fba9a2573dc2f7"],
  },
  {
    crc128: ["ce030d15b5fe2f4", "86b4a7a0780c2431"],
    crc128Seed: ["ee070a9ae5b51db7", "edc293d9595be5d8"],
    crc256: ["3dfc5ec108260a2b", "8afe28c7123bf4e2", "da82ef38023a7a5f", "3e1f77b0174b77c3"],
  },
  {
    crc128: ["64fd1bc011e5bab7", "5c9e858728015568"],
    crc128Seed: ["97ac42c2b00b29b1", "7f89caf08c109aee"],
    crc256: ["9a8af34fd0e9dacf", "bbc54161aa1507e0", "7cda723ccbbfe5ee", "2c289d839fb93f58"],
  },
  {
    crc128: ["fdfa836b41dcef62", "2f8db8030e847e1b"],
    crc128Seed: ["5ba0a49ac4f9b0f8", "dae897ed3e3fce44"],
    crc256: ["9c432e31aef626e7", "9a36e1c6cd6e3dd", "5095a167c34d19d", "a70005cfa6babbea"],
  },
  {
    crc128: ["7d222caae025158a", "cc028d5fd40241b9"],
    crc128Seed: ["dd42515b639e6f97", "e08e86531a58f87f"],
    crc256: ["d93612c835b37d7b", "91dd61729b2fa7f4", "ba765a1bdda09db7", "55258b451b2b1297"],
  },
  {
    crc128: ["80395e48739e1a67", "74a67d8f7f43c3d7"],
    crc128Seed: ["dd2bdd1d62246c6e", "a1f44298ba80acf6"],
    crc256: ["ad86d86c187bf38", "26feea1f2eee240d", "ed7f1fd066b23897", "a768cf1e0fbb502"],
  },
  {
    crc128: ["133b299a939745c5", "796e2aac053f52b3"],
    crc128Seed: ["e8d9fe1521a4a222", "819a8863e5d1c290"],
    crc256: ["c0737f0fe34d36ad", "e6d6d4a267a5cc31", "98300a7911674c23", "bef189661c257098"],
  },
  {
    crc128: ["fd1a9ba5e71b08a2", "7ac0dc2ed7778533"],
    crc128Seed: ["b543161ff177188a", "492fc08a6186f3f4"],
    crc256: ["fc4745f516afd3b6", "88c30370a53080e", "65a1bb34abc465e2", "abbd14662911c8b3"],
  },
  {
    crc128: ["938f5bbab544d3d6", "d2a95f9f2d376d73"],
    crc128Seed: ["68b2f16149e81aa3", "ad7e32f82d86c79d"],
    crc256: ["4574015ae8626ce2", "455aa6137386a582", "658ad2542e8ec20", "e31d7be2ca35d00"],
  },
  {
    crc128: ["eea5f5a9f74af591", "578710bcc36fbea2"],
    crc128Seed: ["7a8393432188931d", "705cfc5ec7cc172"],
    crc256: ["da85ebe5fc427976", "bfa5c7a454df54c8", "4632b72a81bf66d2", "5dd72877db539ee2"],
  },
  {
    crc128: ["2b826f1a2c08c289", "da50f56863b55e74"],
    crc128Seed: ["b18712f6b3eed83b", "bdc7cc05ab4c685f"],
    crc256: ["9e45fb833d1b0af", "d7213081db29d82e", "d2a6b6c6a09ed55e", "98a7686cba323ca9"],
  },
  {
    crc128: ["effc2663cffc777f", "93214f8f463afbed"],
    crc128Seed: ["a156ef06066f4e4e", "a407b6ed8769d51e"],
    crc256: ["bb2f9ed29745c02a", "981eecd435b36ad9", "461a5a05fb9cdff4", "bd6cb2a87b9f910c"],
  },
  {
    crc128: ["5a4fc2728a9bb671", "ebb971522ec38759"],
    crc128Seed: ["1a5a093e6cf1f72b", "729b057fe784f504"],
    crc256: ["71fcbf42a767f9cf", "114cfe772da6cdd", "60cdf9cb629d9d7a", "e270d10ad088b24e"],
  },
  {
    crc128: ["e777b1fd580582f2", "7b880f58da112699"],
    crc128Seed: ["562c6b189a6333f4", "139d64f88a611d4"],
    crc256: ["53d8ef17eda64fa4", "bf3eded14dc60a04", "2b5c559cf5ec07c5", "8895f7339d03a48a"],
  },
  {
    crc128: ["dd16cd0fbc08393", "29a414a5d8c58962"],
    crc128Seed: ["72793d8d1022b5b2", "2e8e69cf7cbffdf0"],
    crc256: ["3721c0473aa99c9a", "1cff4ed9c31cd91c", "4990735033cc482b", "7fdf8c701c72f577"],
  },
  {
    crc128: ["4260e8c254e9924b", "f197a6eb4591572d"],
    crc128Seed: ["8e867ff0fb7ab27c", "f95502fb503efaf3"],
    crc256: ["30c41876b08e3e22", "958e2419e3cd22f4", "f0f3aa1fe119a107", "481662310a379100"],
  },
  {
    crc128: ["4890a83ee435bc8b", "d8c1c00fceb00914"],
    crc128Seed: ["9e7111ba234f900f", "eb8dbab364d8b604"],
    crc256: ["b3261452963eebb", "6cf94b02792c4f95", "d88fa815ef1e8fc", "2d687af66604c73"],
  },
  {
    crc128: ["8ba0fdd2ffc8b239", "f413b366c1ffe02f"],
    crc128Seed: ["c05b2717c59a8a28", "981188eab4fcc8fb"],
    crc256: ["e563f49a1d9072ba", "3c6a3aa4a26367dc", "ba0db13448653f34", "31065d756074d7d6"],
  },
  {
    crc128: ["cf1edbfe7330e94e", "881945906bcb3cc6"],
    crc128Seed: ["4acf0293244855da", "65ae042c1c2a28c2"],
    crc256: ["b25fa0a1cab33559", "d98e8daa28124131", "fce17f50b9c351b3", "3f995ccf7386864b"],
  },
  {
    crc128: ["f6521b912b368ae6", "a9fe4eff81d03e73"],
    crc128Seed: ["d6f623629f80d1a3", "2b9604f32cb7dc34"],
    crc256: ["2a43d84dcf59c7e2", "d0a197c70c5dae0b", "6e84d4bbc71d76a0", "c7e94620378c6cb2"],
  },
  {
    crc128: ["6b5ffc1f54fecb29", "a8e8e7ad5b9a21d9"],
    crc128Seed: ["c4d5a32cd6aac22d", "d7e274ad22d4a79a"],
    crc256: ["368841ea5731a112", "feaf7bc2e73ca48f", "636fb272e9ea1f6", "5d9cb7580c3f6207"],
  },
  {
    crc128: ["381ee1b7ea534f4e", "da3759828e3de429"],
    crc128Seed: ["3e015d76729f9955", "cbbec51a6485fbde"],
    crc256: ["9b86605281f20727", "fc6fcf508676982a", "3b135f7a813a1040", "d3a4706bea1db9c9"],
  },
  {
    crc128: ["4cc8ed3ada5f0f2", "4a496b77c1f1c04e"],
    crc128Seed: ["9085b0a862084201", "a1894bde9e3dee21"],
    crc256: ["367fb472dc5b277d", "7d39ccca16fc6745", "763f988d70db9106", "a8b66f7fecb70f02"],
  },
  {
    crc128: ["e5d0549802d15008", "424c134ecd0db834"],
    crc128Seed: ["6fc44fd91be15c6c", "a1a5ef95d50e537d"],
    crc256: ["d1e3daf5d05f5308", "4c7f81600eaa1327", "109d1b8d1f9d0d2b", "871e8699e0aeb862"],
  },
  {
    crc128: ["aa0d74d4a98db89b", "36fd486d07c56e1d"],
    crc128Seed: ["d0ad23cbb6660d8a", "1264a84665b35e19"],
    crc256: ["789682bf7d781b33", "6bfa6abd2fb5722d", "6779cb3623d33900", "435ca5214e1ee5f0"],
  },
  {
    crc128: ["28ac84ca70958f7e", "d8ae575a68faa731"],
    crc128Seed: ["2aaaee9b9dcffd4c", "6c7faab5c285c6da"],
    crc256: ["45d94235f99ba78f", "ab5ea16f39497f5b", "fb4d6c86fccbdca3", "8104e6310a5fd2c7"],
  },
  {
    crc128: ["43505ed133be672a", "e8f2f9d973c2774e"],
    crc128Seed: ["677b9b9c7cad6d97", "4e1f5d56ef17b906"],
    crc256: ["eea3a6038f983767", "87109f077f86db01", "ecc1ca41f74d61cc", "34a87e86e83bed17"],
  },
  {
    crc128: ["4344a1a0134afe2", "ff5c17f02b62341d"],
    crc128Seed: ["3214c6a587ce4644", "a905e7ed0629d05c"],
    crc256: ["b5c72690cd716e82", "7c6097649e6ebe7b", "7ceee8c6e56a4dcd", "80ca849dc53eb9e4"],
  },
  {
    crc128: ["489b697fe30aa65f", "4da0fb621fdc7817"],
    crc128Seed: ["dc43583b82c58107", "4b0261debdec3cd6"],
    crc256: ["a9748d7b6c0e016c", "7e8828f7ba4b034b", "da0fa54348a2512a", "ebf9745c0962f9ad"],
  },
  {
    crc128: ["c043e67e6fc64118", "ff0abfe926d844d3"],
    crc128Seed: ["f2a9fe5db2e910fe", "ce352cdc84a964dd"],
    crc256: ["b89bc028aa5e6063", "a354e7fdac04459c", "68d6547e6e980189", "c968dddfd573773e"],
  },
  {
    crc128: ["334c5a25b5903a8c", "4c94fef443122128"],
    crc128Seed: ["743e7d8454655c40", "1ab1e6d1452ae2cd"],
    crc256: ["fec766de4a8e476c", "cc0929da9567e71b", "5f9ef5b5f150c35a", "87659cabd649768f"],
  },
  {
    crc128: ["8bde625a10a8c50d", "eb8271ded1f79a0b"],
    crc128Seed: ["14dc6844f0de7a3c", "f85b2f9541e7e6da"],
    crc256: ["2fe22cfd1683b961", "ea1d75c5b7aa01ca", "9eef60a44876bb95", "950c818e505c6f7f"],
  },
  {
    crc128: ["dd52fc14c8dd3143", "1bc7508516e40628"],
    crc128Seed: ["3059730266ade626", "ffa526822f391c2"],
    crc256: ["e25232d7afc8a406", "d2b8a5a3f3b5f670", "6630f33edb7dfe32", "c71250ba68c4ea86"],
  },
  {
    crc128: ["c1336b92fef91bf6", "80332a3945f33fa9"],
    crc128Seed: ["a0f68b86f726ff92", "a3db5282cf5f4c0b"],
    crc256: ["82640b6fc4916607", "2dc2a3aa1a894175", "8b4c852bdee7cc9", "10b9d0a08b55ff83"],
  },
  {
    crc128: ["497cb912b670f3b", "d963a3f02ff4a5b6"],
    crc128Seed: ["4fccefae11b50391", "42ba47db3f7672f"],
    crc256: ["1d6b655a1889feef", "5f319abf8fafa19f", "715c2e49deb14620", "8d9153082ecdcea4"],
  },
  {
    crc128: ["2fe9fabdbe7fdd4", "755db249a2d81a69"],
    crc128Seed: ["f27929f360446d71", "79a1bf957c0c1b92"],
    crc256: ["3c8a28d4c936c9cd", "df0d3d13b2c6a902", "c76702dd97cd2edd", "1aa220f7be16517"],
  },
  {
    crc128: ["d53fb7e3c93a9e4", "737ae71b051bf108"],
    crc128Seed: ["7ac71feb84c2df42", "3d8075cd293a15b4"],
    crc256: ["bf8cee5e095d8a7c", "e7086b3c7608143a", "e55b0c2fa938d70c", "fffb5f58e643649c"],
  },
  {
    crc128: ["cf7d7f25bd70cd2c", "9464ed9baeb41b4f"],
    crc128Seed: ["b9064f5c3cb11b71", "237e39229b012b20"],
    crc256: ["dd54d3f5d982dffe", "7fc7562dbfc81dbf", "5b0dd1924f70945", "f1760537d8261135"],
  },
  {
    crc128: ["9040e5b936b8661b", "276e08fa53ac27fd"],
    crc128Seed: ["8c944d39c2bdd2cc", "e2514c9802a5743c"],
    crc256: ["e82107b11ac90386", "7d6a22bc35055e6", "fd6ea9d1c438d8ae", "be6015149e981553"],
  },
  {
    crc128: ["8431b1bfd0a2379c", "90383913aea283f9"],
    crc128Seed: ["a6163831eb4924d2", "5f3921b4f9084aee"],
    crc256: ["7a70061a1473e579", "5b19d80dcd2c6331", "6196b97931faad27", "869bf6828e237c3f"],
  },
  {
    crc128: ["c54677a80367125e", "3204fbdba462e606"],
    crc128Seed: ["8563278afc9eae69", "262147dd4bf7e566"],
    crc256: ["2178b63e7ee2d230", "e9c61ad81f5bff26", "9af7a81b3c501eca", "44104a3859f0238f"],
  },
  {
    crc128: ["9598f6ab0683fcc2", "1c805abf7b80e1ee"],
    crc128Seed: ["dec9ac42ee0d0f32", "8cd72e3912d24663"],
    crc256: ["1f025d405f1c1d87", "bf7b6221e1668f8f", "52316f64e692dbb0", "7bf43df61ec51b39"],
  },
  {
    crc128: ["6ba372f4b7ab268b", "8c3237cf1fe243df"],
    crc128Seed: ["3833fc51012903df", "8e31310108c5683f"],
    crc256: ["126593715c2de429", "48ca8f35a3f54b90", "b9322b632f4f8b0", "926bb169b7337693"],
  },
  {
    crc128: ["9a62af3dbba140da", "27857ea044e9dfc1"],
    crc128Seed: ["33abce9da2272647", "b22a7993aaf32556"],
    crc256: ["bf8f88f8019bedf0", "ed2d7f01fb273905", "6b45f15901b481cd", "f88ebb413ba6a8d5"],
  },
  {
    crc128: ["82065c62e6582188", "8ef787fd356f5e43"],
    crc128Seed: ["2922e53e36e17dfa", "9805f223d385010b"],
    crc256: ["692154f3491b787d", "e7e64700e414fbf", "757d4d4ab65069a0", "cd029446a8e348e2"],
  },
  {
    crc128: ["22f2aa3df2221cc", "f66fea90f5d62174"],
    crc128Seed: ["b75defaeaa1dd2a7", "9b994cd9a7214fd5"],
    crc256: ["fac675a31804b773", "98bcb3b820c50fc6", "e14af64d28cf0885", "27466fbd2b360eb5"],
  },
  {
    crc128: ["229b79ab69ae97d", "a87aabc2ec26e582"],
    crc128Seed: ["be2b053721eb26d2", "10febd7f0c3d6fcb"],
    crc256: ["9cc5b9b2f6e3bf7b", "655d8495fe624a86", "6381a9f3d1f2bd7e", "79ebabbfc25c83e2"],
  },
  {
    crc128: ["d332cdb073d8dc46", "272c56466868cb46"],
    crc128Seed: ["7e7fcbe35ca6c3f3", "ee8f51e5a70399d4"],
    crc256: ["16737a9c7581fe7b", "ed04bf52f4b75dcb", "9707ffb36bd30c1a", "1390f236fdc0de3e"],
  },
  {
    crc128: ["702e2afc7f5a1825", "8c49b11ea8151fdc"],
    crc128Seed: ["caf3fef61f5a86fa", "ef0b2ee8649d7272"],
    crc256: ["9e34a4e08d9441e1", "7bdc0cd64d5af533", "a926b14d99e3d868", "fca923a17788cce4"],
  },
  {
    crc128: ["a590b202a7a5807b", "968d2593f7ccb54e"],
    crc128Seed: ["9dd8d669e3e95dec", "ee0cc5dd58b6e93a"],
    crc256: ["ac65d5a9466fb483", "221be538b2c9d806", "5cbe9441784f9fd9", "d4c7d5d6e3c122b8"],
  },
  {
    crc128: ["7432d63888e0c306", "74bbceeed479cb71"],
    crc128Seed: ["6471586599575fdf", "6a859ad23365cba2"],
    crc256: ["f9ceec84acd18dcc", "74a242ff1907437c", "f70890194e1ee913", "777dfcb4bb01f0ba"],
  },
  {
    crc128: ["69db23875cb0b715", "ada8dd91504ae37f"],
    crc128Seed: ["46bf18dbf045ed6a", "e1b5f67b0645ab63"],
    crc256: ["877be8f5dcddff4", "6d471b5f9ca2e2d1", "802c86d6f495b9bb", "a1f9b9b22b3be704"],
  },
  {
    crc128: ["c4af7faf883033aa", "9bd296c4e9453cac"],
    crc128Seed: ["ca45426c1f7e33f9", "a6bbdcf7074d40c5"],
    crc256: ["e13a005d7142733b", "c02b7925c5eeefaf", "d39119a60441e2d5", "3c24c710df8f4d43"],
  },
  {
    crc128: ["42e34cf3d53c7876", "9cddbb26424dc5e"],
    crc128Seed: ["64f6340a6d8eddad", "2196e488eb2a3a4b"],
    crc256: ["c9e9da25911a16fd", "e21b4683f3e196a8", "cb80bf1a4c6fdbb4", "53792e9b3c3e67f8"],
  },
  {
    crc128: ["bcc7a81ed5432429", "b6d7bdc6ad2e81f1"],
    crc128Seed: ["93605ec471aa37db", "a2a73f8a85a8e397"],
    crc256: ["10a012b8ca7ac24b", "aac5fd63351595cf", "5bb4c648a226dea0", "9d11ecb2b5c05c5f"],
  },
  {
    crc128: ["6226a32e25099848", "ea895661ecf53004"],
    crc128Seed: ["4d7e0158db2228b9", "e5a7d82922f69842"],
    crc256: ["2cea7713b69840ca", "18de7b9ae938375b", "f127cca08f3cc665", "b1c22d727665ad2"],
  },
  {
    crc128: ["ca6552a0dfb82c73", "b024cdf09e34ba07"],
    crc128Seed: ["66cd8c5a95d7393b", "e3939acf790d4a74"],
    crc256: ["97827541a1ef051e", "ac2fce47ebe6500c", "b3f06d3bddf3bd6a", "1d74afb25e1ce5fe"],
  },
  {
    crc128: ["f14ef7f47d8a57a3", "80d1f86f2e061d7c"],
    crc128Seed: ["401d6c2f151b5a62", "e988460224108944"],
    crc256: ["7804d4135f68cd19", "5487b4b39e69fe8e", "8cc5999015358a27", "8f3729b61c2d5601"],
  },
  {
    crc128: ["c8389799445480db", "5389f5df8aacd50d"],
    crc128Seed: ["d136581f22fab5f", "c2f31f85991da417"],
    crc256: ["aefbf9ff84035a43", "8accbaf44adadd7c", "e57f3657344b67f5", "21490e5e8abdec51"],
  },
  {
    crc128: ["70bd1968996bffc2", "4c613de5d8ab32ac"],
    crc128Seed: ["fe1f4f97206f79d8", "ac0434f2c4e213a9"],
    crc256: ["7490e9d82cfe22ca", "5fbbf7f987454238", "c39e0dc8368ce949", "22201d3894676c71"],
  },
  {
    crc128: ["8eeb177a86053c11", "e390122c345f34a2"],
    crc128Seed: ["1e30e47afbaaf8d6", "7b892f68e5f91732"],
    crc256: ["b87922525fa44158", "f440a1ee1a1a766b", "ee8efad279d08c5c", "421f910c5b60216e"],
  },
  {
    crc128: ["27233b28b5b11e9b", "c7dfe8988a942700"],
    crc128Seed: ["570ed11c4abad984", "4b4c04632f48311a"],
    crc256: ["12f33235442cbf9", "a35315ca0b5b8cdb", "d8abde62ead5506b", "fc0fcf8478ad5266"],
  },
  {
    crc128: ["49fa3070bc7b06d0", "f12ed446bd0c0539"],
    crc128Seed: ["6d43ac5d1dd4b240", "7609524fe90bec93"],
    crc256: ["391c2b2e076ec241", "f5e62deda7839f7b", "3c7b3186a10d870f", "77ef4f2cba4f1005"],
  },
  {
    crc128: ["57466046cf6896ed", "8ac37e0e8b25b0c6"],
    crc128Seed: ["3e6074b52ad3cf18", "aa491ce7b45db297"],
    crc256: ["f7a9227c5e5e22c3", "3d92e0841e29ce28", "2d30da5b2859e59d", "ff37fa1c9cbfafc2"],
  },
  {
    crc128: ["c2dcc9758c910171", "cb5cddaeff4ddb40"],
    crc128Seed: ["5d7cc5869baefef1", "9644c5853af9cfeb"],
    crc256: ["255c968184694ee1", "4e4d726eda360927", "7d27dd5b6d100377", "9a300e2020ddea2c"],
  },
  {
    crc128: ["3ee84d3d5b4ca00b", "5cbc6d701894c3f9"],
    crc128Seed: ["d9e946f5ae1ca95", "24ca06e67f0b1833"],
    crc256: ["3413d46b4152650e", "cbdfdbc2ab516f9c", "2aad8acb739e0c6c", "2bfc950d9f9fa977"],
  },
  {
    crc128: ["6b11c5073687208", "7e0a57de0d453f3"],
    crc128Seed: ["e48c267d4f646867", "2168e9136375f9cb"],
    crc256: ["64da194aeeea7fdf", "a3b9f01fa5885678", "c316f8ee2eb2bd17", "a7e4d80f83e4427f"],
  },
  {
    crc128: ["7da9e81d89fda7ad", "274157cabe71440d"],
    crc128Seed: ["2c22d9a480b331f7", "e835c8ac746472d5"],
    crc256: ["2038ce817a201ae4", "46f3289dfe1c5e40", "435578a42d4b7c56", "f96d9f409fcf561"],
  },
  {
    crc128: ["d45a938b79f54e8f", "366b219d6d133e48"],
    crc128Seed: ["5b14be3c25c49405", "fdd791d48811a572"],
    crc256: ["3de67b8d9e95d335", "903c01307cfbeed5", "af7d65f32274f1d1", "4dba141b5fc03c42"],
  },
  {
    crc128: ["c83d3c5f4e5f0320", "694e7adeb2bf32e5"],
    crc128Seed: ["7ad09538a3da27f5", "2b5c18f934aa5303"],
    crc256: ["c4dad7703d34326e", "825569e2bcdc6a25", "b83d267709ca900d", "44ed05151f5d74e6"],
  },
  {
    crc128: ["bc271bc0df14d647", "b071100a9ff2edbb"],
    crc128Seed: ["2b1a4c1cc31a119a", "b5d7caa1bd946cef"],
    crc256: ["e02623ae10f4aadd", "d79f600389cd06fd", "1e8da7965303e62b", "86f50e10eeab0925"],
  },
  {
    crc128: ["336c1b59a1fc19f6", "c173acaecc471305"],
    crc128Seed: ["db1267d24f3f3f36", "e9a5ee98627a6e78"],
    crc256: ["718f334204305ae5", "e3b53c148f98d22c", "a184012df848926", "6e96386127d51183"],
  },
  {
    crc128: ["84064a6dcf916340", "fbf55a26790e0ebb"],
    crc128Seed: ["2e7f84151c31a5c2", "9f7f6d76b950f9bf"],
    crc256: ["125e094fbee2b146", "5706aa72b2eef7c2", "1c4a2daa905ee66e", "83d48029b5451694"],
  },
  {
    crc128: ["e38e526cd3324364", "85f2b63a5b5e840a"],
    crc128Seed: ["485d7cef5aaadd87", "d2b837a462f6db6d"],
    crc256: ["3e41cef031520d9a", "82df73902d7f67e", "3ba6fd54c15257cb", "22f91f079be42d40"],
  },
  {
    crc128: ["16818ee9d38c6664", "5519fa9a1e35a329"],
    crc128Seed: ["cbd0001e4b08ed8", "41a965e37a0c731b"],
    crc256: ["66e7b5dcca1ca28f", "963b2d993614347d", "9b6fc6f41d411106", "aaaecaccf7848c0c"],
  },
  {
    crc128: ["30278016830ddd43", "f046646d9012e074"],
    crc128Seed: ["c62a5804f6e7c9da", "98d51f5830e2bc1e"],
    crc256: ["7b2cbe5d37e3f29e", "7b8c3ed50bda4aa0", "3ea60cc24639e038", "f7706de9fb0b5801"],
  },
  {
    crc128: ["7d2782b82bd494b6", "97159ba1c26b304b"],
    crc128Seed: ["42b3b0fd431b2ac2", "faa81f82691c830c"],
    crc256: ["7cc6449234c7e185", "aeaa6fa643ca86a5", "1412db1c0f2e0133", "4df2fe3e4072934f"],
  },
  {
    crc128: ["58c8aba7475e2d95", "3e2f291698c9427a"],
    crc128Seed: ["e8710d19c9de9e41", "65dda22eb04cf953"],
    crc256: ["d7729c48c250cffa", "ef76162b2ddfba4b", "52371e17f4d51f6d", "ddd002112ff0c833"],
  },
  {
    crc128: ["d1090893afaab8bc", "96c4fe6922772807"],
    crc128Seed: ["4522426c2b4205eb", "efad99a1262e7e0d"],
    crc256: ["c7696029abdb465e", "4e18eaf03d517651", "d006bced54c86ac8", "4330326d1021860c"],
  },
  {
    crc128: ["fc947167f69c0da5", "ae79cfdb91b6f6c1"],
    crc128Seed: ["7b251d04c26cbda3", "128a33a79060d25e"],
    crc256: ["1eca842dbfe018dd", "50a4cd2ee0ba9c63", "c2f5c97d8399682f", "3f929fc7cbe8ecbb"],
  },
  {
    crc128: ["b7609c8e70386d66", "36e6ccc278d1636d"],
    crc128Seed: ["2f873307c08e6a1c", "10f252a758505289"],
    crc256: ["c8977646e81ab4b6", "8017b745cd80213b", "960687db359bea0", "ef4a470660799488"],
  },
  {
    crc128: ["4c10537443152f3d", "720451d3c895e25d"],
    crc128Seed: ["aff60c4d11f513fd", "881e8d6d2d5fb953"],
    crc256: ["9dec034a043f1f55", "e27a0c22e7bfb39d", "2220b959128324", "53240272152dbd8b"],
  },
  {
    crc128: ["f265edb0c1c411d7", "30e1e9ec5262b7e6"],
    crc128Seed: ["c2c3ba061ce7957a", "d975f93b89a16409"],
    crc256: ["e9d703123f43450a", "41383fedfed67c82", "6e9f43ecbbbd6004", "c7ccd23a24e77b8"],
  },
  {
    crc128: ["e9369d2e9007e74b", "b1375915d1136052"],
    crc128Seed: ["926c2021fe1d2351", "1d943addaaa2e7e6"],
    crc256: ["f5f515869c246738", "7e309cd0e1c0f2a0", "153c3c36cf523e3b", "4931c66872ea6758"],
  },
  {
    crc128: ["301d7a61c4b3dbca", "861336c3f0552d61"],
    crc128Seed: ["12c6db947471300f", "a679ef0ed761deb9"],
    crc256: ["5f713b720efcd147", "37ac330a333aa6b", "3309dc9ec1616eef", "52301d7a908026b5"],
  },
  {
    crc128: ["6cef866ec295abea", "c486c0d9214beb2d"],
    crc128Seed: ["d6e490944d5fe100", "59df3175d72c9f38"],
    crc256: ["3f23aeb4c04d1443", "9bf0515cd8d24770", "958554f60ccaade2", "5182863c90132fe8"],
  },
  {
    crc128: ["fcfb9443e997cab", "f13310d96dec2772"],
    crc128Seed: ["709cad2045251af2", "afd0d30cc6376dad"],
    crc256: ["59d4bed30d550d0d", "58006d4e22d8aad1", "eee12d2362d1f13b", "35cf1d7faaf1d228"],
  },
  {
    crc128: ["73119c99e6d508be", "5d4036a187735385"],
    crc128Seed: ["8fa66e192fd83831", "2abf64b6b592ed57"],
    crc256: ["d4501f95dd84b08c", "bf1552439c8bea02", "4f56fe753ba7e0ba", "4ca8d35cc058cfcd"],
  },
  {
    crc128: ["aafcb77497b5a20b", "411819e5e79b77a3"],
    crc128Seed: ["bd779579c51c77ce", "58d11f5dcf5d075d"],
    crc256: ["9eae76cde1cb4233", "32fe25a9bf657970", "1c0c807948edb06a", "b8f29a3dfaee254d"],
  },
  {
    crc128: ["3f44f873be4812ec", "427662c1dbfaa7b2"],
    crc128Seed: ["a207ff9638fb6558", "a738d919e45f550f"],
    crc256: ["cb186ea05717e7d6", "1ca7d68a5871fdc1", "5d4c119ea8ef3750", "72b6a10fa2ff9406"],
  },
  {
    crc128: ["d396a297799c24a1", "8fee992e3069bad5"],
    crc128Seed: ["2e3a01b0697ccf57", "ee9c7390bd901cfa"],
    crc256: ["56f2d9da0af28af2", "3fdd37b2fe8437cb", "3d13eeeb60d6aec0", "2432ae62e800a5ce"],
  },
  {
    crc128: ["895fe8443183da74", "c7f2f6f895a67334"],
    crc128Seed: ["a0d6b6a506691d31", "24f51712b459a9f0"],
    crc256: ["173a699481b9e088", "1dee9b77bcbf45d3", "32b98a646a8667d0", "3adcd4ee28f42a0e"],
  },
  {
    crc128: ["a3d5d1137d30c4bd", "1e7d706a49bdfb9e"],
    crc128Seed: ["c63282b20ad86db2", "aec97fa07916bfd6"],
    crc256: ["7c9ba3e52d44f73e", "af62fd245811185d", "8a9d2dacd8737652", "bd2cce277d5fbec0"],
  },
  {
    crc128: ["b22bf08d9f8aecf7", "c182730de337b922"],
    crc128Seed: ["2b9adc87a0450a46", "192c29a9cfc00aad"],
    crc256: ["9fd733f1d84a59d9", "d86bd5c9839ace15", "af20b57303172876", "9f63cb7161b5364c"],
  },
  {
    crc128: ["882efc2561715a9c", "ef8132a18a540221"],
    crc128Seed: ["b20a3c87a8c257c1", "f541b8628fad6c23"],
    crc256: ["9552aed57a6e0467", "4d9fdd56867611a7", "c330279bf23b9eab", "44dbbaea2fcb8eba"],
  },
  {
    crc128: ["371a98b2cb084883", "33a2886ee9f00663"],
    crc128Seed: ["be9568818ed6e6bd", "f244a0fa2673469a"],
    crc256: ["b447050bd3e559e9", "d3b695dae7a13383", "ded0bb65be471188", "ca3c7a2b78922cae"],
  },
  {
    crc128: ["89f3aab99afbd636", "f420e004f8148b9a"],
    crc128Seed: ["6818073faa797c7c", "dd3b4e21cbbf42ca"],
    crc256: ["6a2b7db261164844", "cbead63d1895852a", "93d37e1eae05e2f9", "5d06db2703fbc3ae"],
  },
  {
    crc128: ["21c2be098327f49b", "7e035065ac7bbef5"],
    crc128Seed: ["6d7348e63023fb35", "9d427dc1b67c3830"],
    crc256: ["4e3d018a43858341", "cf924bb44d6b43c5", "4618b6a26e3446ae", "54d3013fac3ed469"],
  },
  {
    crc128: ["9d097dd3152ab107", "51e21d24126e8563"],
    crc128Seed: ["cba56cac884a1354", "39abb1b595f0a977"],
    crc256: ["81e6dd1c1109848f", "1644b209826d7b15", "6ac67e4e4b4812f0", "b3a9f5622c935bf7"],
  },
  {
    crc128: ["c1a78b82ba815b74", "458cbdfc82eb322a"],
    crc128Seed: ["17f4a192376ed8d7", "6f9e92968bc8ccef"],
    crc256: ["93e098c333b39905", "d59b1cace44b7fdc", "f7a64ed78c64c7c5", "7c6eca5dd87ec1ce"],
  },
  {
    crc128: ["5aeead8d6cb25bb9", "739315f7743ec3ff"],
    crc128Seed: ["9ab48d27111d2dcc", "5b87bd35a975929b"],
    crc256: ["c3dd8d6d95a46bb3", "7bf9093215a4f483", "cb557d6ed84285bd", "daf58422f261fdb5"],
  },
  {
    crc128: ["ba1ffba29f0367aa", "a20bec1dd15a8b6c"],
    crc128Seed: ["e9bf61d2dab0f774", "f4f35bf5870a049c"],
    crc256: ["26787efa5b92385", "3d9533590ce30b59", "a4da3e40530a01d4", "6395deaefb70067c"],
  },
  {
    crc128: ["d8ad7ec84a9c9aa2", "e256cffed11f69e6"],
    crc128Seed: ["2cf65e4958ad5bda", "cfbf9b03245989a7"],
    crc256: ["9fa51e6686cf4444", "9425c117a34609d5", "b25f7e2c6f30e96", "ea5477c3f2b5afd1"],
  },
  {
    crc128: ["361e0a62c8187bff", "6089971bb84d7133"],
    crc128Seed: ["93df7741588dd50b", "c2a9b6abcd1d80b1"],
    crc256: ["4d2f86869d79bc59", "85cd24d8aa570ff", "b0dcf6ef0e94bbb5", "2037c69aa7a78421"],
  },
  {
    crc128: ["4ec02f3d2f2b23f2", "ab3580708aa7c339"],
    crc128Seed: ["cdce066fbab3f65", "d8ed3ecf3c7647b9"],
    crc256: ["6d2204b3e31f344a", "61a4d87f80ee61d7", "446c43dbed4b728f", "73130ac94f58747e"],
  },
  {
    crc128: ["c2c9fc637dbdfcfa", "292ab8306d149d75"],
    crc128Seed: ["7f436b874b9ffc07", "a5b56b0129218b80"],
    crc256: ["9188f7bdc47ec050", "cfe9345d03a15ade", "40b520fb2750c49e", "c2e83d343968af2e"],
  },
  {
    crc128: ["e1a8286a7d67946e", "52bd956f047b298"],
    crc128Seed: ["cbd74332dd4204ac", "12b5be7752721976"],
    crc256: ["278426e27f6204b6", "932ca7a7cd610181", "41647321f0a5914d", "48f4aa61a0ae80db"],
  },
  {
    crc128: ["bde51033ac0413f8", "bc0272f691aec629"],
    crc128Seed: ["6204332651bebc44", "1cbf00de026ea9bd"],
    crc256: ["b9c7ed6a75f3ff1e", "7e310b76a5808e4f", "acbbd1aad5531885", "fc245f2473adeb9c"],
  },
  {
    crc128: ["6c71064996cbec8b", "352c535edeefcb89"],
    crc128Seed: ["ac7f0aba15cd5ecd", "3aba1ca8353e5c60"],
    crc256: ["5c30a288a80ce646", "c2940488b6617674", "925f8cc66b370575", "aa65d1283b9bb0ef"],
  },
  {
    crc128: ["43e47bd5bab1e0ef", "4a71f363421f282f"],
    crc128Seed: ["880b2f32a2b4e289", "1299d4eda9d3eadf"],
    crc256: ["d713a40226f5564", "4d8d34fedc769406", "a85001b29cd9cac3", "cae92352a41fd2b0"],
  },
  {
    crc128: ["832954ec9d0de333", "94c390aa9bcb6b8a"],
    crc128Seed: ["f3b32afdc1f04f82", "d229c3b72e4b9a74"],
    crc256: ["1d11860d7ed624a6", "cadee20b3441b984", "75307079bf306f7b", "87902aa3b9753ba4"],
  },
  {
    crc128: ["4960111789727567", "149b8a37c7125ab6"],
    crc128Seed: ["78c7a13ab9749382", "1c61131260ca151a"],
    crc256: ["1e93276b35c309a0", "2618f56230acde58", "af61130a18e4febf", "7145deb18e89befe"],
  },
  {
    crc128: ["6566d74954986ba5", "99d5235cc82519a7"],
    crc128Seed: ["257a23805c2d825", "ad75ccb968e93403"],
    crc256: ["b45bd4cf78e11f7f", "80c5536bdc487983", "a4fd76ecbf018c8a", "3b9dac78a7a70d43"],
  },
  {
    crc128: ["c8a2827404991402", "7ee5e78550f02675"],
    crc128Seed: ["2ec53952db5ac662", "1526405a9df6794b"],
    crc256: ["eddc6271170c5e1f", "f5a85f986001d9d6", "95427c677bf58d58", "53ed666dfa85cb29"],
  },
  {
    crc128: ["3edbc10e4bfee91b", "f0d681304c28ef68"],
    crc128Seed: ["77ea602029aaaf9c", "90f070bd24c8483c"],
    crc256: ["28bc8e41e08ceb86", "1eb56e48a65691ef", "9fea5301c9202f0e", "3fcb65091aa9f135"],
  },
  {
    crc128: ["83707730cad725d4", "c9ca88c3a779674a"],
    crc128Seed: ["e1c696fbbd9aa933", "723f3baab1c17a45"],
    crc256: ["f82abc7a1d851682", "30683836818e857d", "78bfa3e89a5ab23f", "6928234482b31817"],
  },
  {
    crc128: ["1ef8e98e1ea57269", "5971116272f45a8b"],
    crc128Seed: ["187ad68ce95d8eac", "e94e93ee4e8ecaa6"],
    crc256: ["a0ff2a58611838b5", "b01e03849bfbae6f", "d081e202e28ea3ab", "51836bcee762bf13"],
  },
  {
    crc128: ["3eeb60c3f5f8143d", "a25aec05c422a24f"],
    crc128Seed: ["b026b03ad3cca4db", "e6e030028cc02a02"],
    crc256: ["16fe679338b34bfc", "c1be385b5c8a9de4", "65af5df6567530eb", "ed3b303df4dc6335"],
  },
  {
    crc128: ["36a8d13a2cbb0939", "254ac73907413230"],
    crc128Seed: ["73520d1522315a70", "8c9fdb5cf1e1a507"],
    crc256: ["b3640570b926886", "fba2344ee87f7bab", "de57341ab448df05", "385612ee094fa977"],
  },
  {
    crc128: ["5b2b7ca856fad1c3", "8093022d682e375d"],
    crc128Seed: ["ea5d163ba7ea231f", "d6181d012c0de641"],
    crc256: ["e7d40d0ab8b08159", "2e82320f51b3a67e", "27c2e356ea0b63a3", "58842d01a2b1d077"],
  },
  {
    crc128: ["48b218e3b721810d", "d3757ac8609bc7fc"],
    crc128Seed: ["111ba02a88aefc8", "e86343137d3bfc2a"],
    crc256: ["44ad26b51661b507", "db1268670274f51e", "62a5e75beae875f3", "e266e7a44c5f28c6"],
  },
  {
    crc128: ["15747d8c505ffd00", "438a15f391312cd6"],
    crc128Seed: ["e46ca62c26d821f5", "be78d74c9f79cb44"],
    crc256: ["a8aa19f3aa59f09a", "effb3cddab2c9267", "d78e41ad97cb16a5", "ace6821513527d32"],
  },
  {
    crc128: ["d9ccef1d4be46988", "5ede0c4e383a5e66"],
    crc128Seed: ["da69683716a54d1e", "bfc3fdf02d242d24"],
    crc256: ["20ed30274651b3f5", "4c659824169e86c6", "637226dae5b52a0e", "7e050dbd1c71dc7f"],
  },
  {
    crc128: ["2870a99c76a587a4", "99f74cc0b182dda4"],
    crc128Seed: ["8a5e895b2f0ca7b6", "3d78882d5e0bb1dc"],
    crc256: ["f466123732a3e25e", "aca5e59716a40e50", "261d2e7383d0e686", "ce9362d6a42c15a7"],
  },
  {
    crc128: ["a3335c417687cf3a", "92ff114ac45cda75"],
    crc128Seed: ["c3b8a627384f13b5", "c4f25de33de8b3f7"],
    crc256: ["eacbf520578c5964", "4cb19c5ab24f3215", "e7d8a6f67f0c6e7", "325c2413eb770ada"],
  },
  {
    crc128: ["c7cd48f7abf1fe59", "ce600656ace6f53a"],
    crc128Seed: ["8a94a4381b108b34", "f9d1276c64bf59fb"],
    crc256: ["219ce70ff5a112a5", "e6026c576e2d28d7", "b8e467f25015e3a6", "950cb904f37af710"],
  },
  {
    crc128: ["d803e1eead47604c", "ad00f7611970a71b"],
    crc128Seed: ["bc50036b16ce71f5", "afba96210a2ca7d6"],
    crc256: ["28f7a7be1d6765f0", "97bd888b93938c68", "6ad41d1b407ded49", "b9bfec098dc543e4"],
  },
  {
    crc128: ["d17c928c5342477f", "745130b795254ad5"],
    crc128Seed: ["8c5db926fe88f8ba", "742a95c953e6d974"],
    crc256: ["279db8057b5d3e96", "98168411565b4ec4", "50a72c54fa1125fa", "27766a635db73638"],
  },
  {
    crc128: ["6531c1fe32bcb417", "8c970d8df8cdbeb4"],
    crc128Seed: ["917ba5fc67e72b40", "4b65e4e263e0a426"],
    crc256: ["e0de33ce88a8b3a9", "f8ef98a437e16b08", "a5162c0c7c5f7b62", "dbdac43361b2b881"],
  },
  {
    crc128: ["ffe319654c8e7ebc", "6a67b8f13ead5a72"],
    crc128Seed: ["6dd10a34f80d532f", "6e9cfaece9fbca4"],
    crc256: ["b4468eb6a30aa7e9", "e87995bee483222a", "d036c2c90c609391", "853306e82fa32247"],
  },
  {
    crc128: ["8950cfcf4bdf622c", "8847dca82efeef2f"],
    crc128Seed: ["646b75b026708169", "21cab4b1687bd8b"],
    crc256: ["243b489a9eae6231", "5f3e634c4b779876", "ff8abd1548eaf646", "c7962f5f0151914b"],
  },
  {
    crc128: ["14453b5cc3d82396", "4ef700c33ed278bc"],
    crc128Seed: ["1639c72ffc00d12e", "fb140ee6155f700d"],
    crc256: ["2e6b5c96a6620862", "a1f136998cbe19c", "74e058a3b6c5a712", "93dcf6bd33928b17"],
  },
  {
    crc128: ["276aa37744b5a028", "8c10800ee90ea573"],
    crc128Seed: ["e6e57d2b33a1e0b7", "91f83563cd3b9dda"],
    crc256: ["afbb4739570738a1", "440ba98da5d8f69", "fde4e9b0eda20350", "e67dfa5a2138fa1"],
  },
  {
    crc128: ["ff5c03f003c1fefe", "e1098670afe7ff6"],
    crc128Seed: ["ea445030cf86de19", "f155c68b5c2967f8"],
    crc256: ["95d31b145dbb2e9e", "914fe1ca3deb3265", "6066020b1358ccc1", "c74bb7e2dee15036"],
  },
  {
    crc128: ["e2164451c651adfb", "b2534e65477f9823"],
    crc128Seed: ["4d70691a69671e34", "15be4963dbde8143"],
    crc256: ["762e75c406c5e9a3", "7b7579f7e0356841", "480533eb066dfce5", "90ae14ea6bfeb4ae"],
  },
  {
    crc128: ["ad159f542d81f04e", "49626a97a946096"],
    crc128Seed: ["d8d3998bf09fd304", "d127a411eae69459"],
    crc256: ["8f3253c4eb785a7b", "4049062f37e62397", "b9fa04d3b670e5c1", "1211a7967ac9350f"],
  },
  {
    crc128: ["3712eb913d04e2f2", "2f9500d319c84d89"],
    crc128Seed: ["4ac6eb21a8cf06f9", "7d1917afcde42744"],
    crc256: ["6b58604b5dd10903", "c4288dfbc1e319fc", "230f75ca96817c6e", "8894cba3b763756c"],
  },
  {
    crc128: ["a3c1c5ca1b0367", "eb6933997272bb3d"],
    crc128Seed: ["76a72cb62692a655", "140bb5531edf756e"],
    crc256: ["8d0d8067d1c925f4", "7b3fa56d8d77a10c", "2bd00287b0946d88", "f08c8e4bd65b8970"],
  },
  {
    crc128: ["5aa82bfaa99d3978", "c18f96cade5ce18d"],
    crc128Seed: ["38404491f9e34c03", "891fb8926ba0418c"],
    crc256: ["e5f69a6398114c15", "7b8ded3623bc6b1d", "2f3e5c5da5ff70e8", "1ab142addea6a9ec"],
  },
  {
    crc128: ["8b305d532e61226e", "caeae80da2ea2e"],
    crc128Seed: ["88a6289a76ac684e", "8ce5b5f9df1cbd85"],
    crc256: ["8ae1fc4798e00d57", "e7164b8fb364fc46", "6a978c9bd3a66943", "ef10d5ae4dd08dc"],
  },
  {
    crc128: ["751390a8a5c41bdc", "6ee5fbf87605d34"],
    crc128Seed: ["6ca73f610f3a8f7c", "e898b3c996570ad"],
    crc256: ["98168a5858fc7110", "6f987fa27aa0daa2", "f25e3e180d4b36a3", "d0b03495aeb1be8a"],
  },
  {
    crc128: ["b87a326e413604bf", "d8f9a5fa214b03ab"],
    crc128Seed: ["8a8bb8265771cf88", "a655319054f6e70f"],
    crc256: ["b499cb8e65a9af44", "bee7fafcc8307491", "5d2e55fa9b27cda2", "63b120f5fb2d6ee5"],
  },
  {
    crc128: ["5df25f13ea7bc284", "165edfaafd2598fb"],
    crc128Seed: ["af7215c5c718c696", "e9f2f9ca655e769"],
    crc256: ["e459cfcb565d3d2d", "41d032631be2418a", "c505db05fd946f60", "54990394a714f5de"],
  },
  {
    crc128: ["58eb4d03b2c3ddf5", "6d2542995f9189f1"],
    crc128Seed: ["c0beec58a5f5fea2", "ed67436f42e2a78b"],
    crc256: ["dfec763cdb2b5193", "724a8d5345bd2d6", "94d4fd1b81457c23", "28e87c50cdede453"],
  },
  {
    crc128: ["7f759dddc6e8549a", "616dd0ca022c8735"],
    crc128Seed: ["94717ad4bc15ceb3", "f66c7be808ab36e"],
    crc256: ["af8286b550b2f4b7", "745bd217d20a9f40", "c73bfb9c5430f015", "55e65922666e3fc2"],
  },
  {
    crc128: ["f271ba474edc562d", "e6596e67f9dd3ebd"],
    crc128Seed: ["c0a288edf808f383", "b3def70681c6babc"],
    crc256: ["7da7864e9989b095", "bf2f8718693cd8a1", "264a9144166da776", "61ad90676870beb6"],
  },
  {
    crc128: ["45744afcf131dbee", "97222392c2559350"],
    crc128Seed: ["498a19b280c6d6ed", "83ac2c36acdb8d49"],
    crc256: ["7a69645c294daa62", "abe9d2be8275b3d2", "39542019de371085", "7f4efac8488cd6ad"],
  },
  {
    crc128: ["b6dd09ba7851c7af", "570de4e1bb13b133"],
    crc128Seed: ["c4e784eb97211642", "8285a7fcdcc7c58d"],
    crc256: ["d421f47990da899b", "8aed409c997eaa13", "7a045929c2e29ccf", "b373682a6202c86b"],
  },
  {
    crc128: ["216e1d6c86cb524c", "d01cf6fd4f4065c0"],
    crc128Seed: ["fffa4ec5b482ea0f", "a0e20ee6a5404ac1"],
    crc256: ["c1b037e4eebaf85e", "634e3d7c3ebf89eb", "bcda972358c67d1", "fd1352181e5b8578"],
  },
  {
    crc128: ["bceee07c11a9ac30", "2e2d47dff8e77eb7"],
    crc128Seed: ["11a394cd7b6d614a", "1d7c41d54e15cb4a"],
    crc256: ["15baa5ae7312b0fc", "f398f596cc984635", "8ab8fdf87a6788e8", "b2b5c1234ab47e2"],
  },
  {
    crc128: ["bd2b31b5608143fe", "ab717a10f2554853"],
    crc128Seed: ["293857f04d194d22", "d51be8fa86f254f0"],
    crc256: ["1eee39e07686907e", "639039fe0e8d3052", "d6ec1470cef97ff", "370c82b860034f0f"],
  },
  {
    crc128: ["b9e0d415b4ebd534", "c97c2a27efaa33d7"],
    crc128Seed: ["591cdb35f84ef9da", "a57d02d0e8e3756c"],
    crc256: ["23f55f12d7c5c87b", "4c7ca0fe23221101", "dbc3020480334564", "d985992f32c236b1"],
  },
  {
    crc128: ["2228d6725e31b8ab", "9b98f7e4d0142e70"],
    crc128Seed: ["b6a8c2115b8e0fe7", "b591e2f5ab9b94b1"],
    crc256: ["6c1feaa8065318e0", "4e7e2ca21c2e81fb", "e9fe5d8ce7993c45", "ee411fa2f12cf8df"],
  },
  {
    crc128: ["87049e68f5d38e59", "7d8ce44ec6bd7751"],
    crc128Seed: ["cc28d08ab414839c", "6c8f0bd34fe843e3"],
    crc256: ["b8496dcdc01f3e47", "2f03125c282ac26", "82a8797ba3f5ef07", "7c977a4d10bf52b8"],
  },
  {
    crc128: ["98d0dbf796480187", "fbcb5f3e1bef5742"],
    crc128Seed: ["5af2a0463bf6e921", "ad9555bf0120b3a3"],
    crc256: ["283e39b3dc99f447", "bedaa1a4a0250c28", "9d50546624ff9a57", "4abaf523d1c090f6"],
  },
  {
    crc128: ["57c5208e8f021a77", "f7653fbb69cd9276"],
    crc128Seed: ["a484410af21d75cb", "f19b6844b3d627e8"],
    crc256: ["f37400fc3ffd9514", "36ae0d821734edfd", "5f37820af1f1f306", "be637d40e6a5ad0"],
  },
  {
    crc128: ["68110a7f83f5d3ff", "6d77e045901b85a8"],
    crc128Seed: ["84ef681113036d8b", "3b9f8e3928f56160"],
    crc256: ["fc8b7f56c130835", "a11f3e800638e841", "d9572267f5cf28c1", "7897c8149803f2aa"],
  },
  {
    crc128: ["d1bfe4df12b04cbf", "f58c17243fd63842"],
    crc128Seed: ["3a453cdba80a60af", "5737b2ca7470ea95"],
    crc256: ["54d44a3f4477030c", "8168e02d4869aa7f", "77f383a17778559d", "95e1737d77a268fc"],
  },
  {
    crc128: ["61c9c95d91017da5", "16f7c83ba68f5279"],
    crc128Seed: ["9c0619b0808d05f7", "83c117ce4e6b70a3"],
    crc256: ["cfb4c8af7fd01413", "fdef04e602e72296", "ed6124d337889b1", "4919c86707b830da"],
  },
  {
    crc128: ["58634004c7b2d19a", "24bb5f51ed3b9073"],
    crc128Seed: ["46409de018033d00", "4a9805eed5ac802e"],
    crc256: ["e18de8db306baf82", "46bbf75f1fa025ff", "5faf2fb09be09487", "3fbc62bd4e558fb3"],
  },
  {
    crc128: ["29c3529eb165eeba", "443de3703b657c35"],
    crc128Seed: ["66acbce31ae1bc8d", "1acc99effe1d547e"],
    crc256: ["cf07f8a57906573d", "31bafb0bbb9a86e7", "40c69492702a9346", "7df61fdaa0b858af"],
  },
  {
    crc128: ["ae59ca86f4c3323d", "25906c09906d5c4c"],
    crc128Seed: ["8dd2aa0c0a6584ae", "232a7d96b38f40e9"],
    crc256: ["8986ee00a2ed0042", "c49ae7e428c8a7d1", "b7dd8280713ac9c2", "e018720aed1ebc28"],
  },
  {
    crc128: ["d4edc954c07cd8f3", "224f47e7c00a30ab"],
    crc128Seed: ["d5ad7ad7f41ef0c6", "59e089281d869fd7"],
    crc256: ["f29340d07a14b6f1", "c87c5ef76d9c4ef3", "463118794193a9a", "2922dcb0540f0dbc"],
  },
  {
    crc128: ["b1b7ec44f9302176", "5cb476450dc0c297"],
    crc128Seed: ["dc5ef652521ef6a2", "3cc79a9e334e1f84"],
    crc256: ["769e2a283dbcc651", "9f24b105c8511d3f", "c31c15575de2f27e", "ecfecf32c3ae2d66"],
  },
  {
    crc128: ["54bc9bee7cbe1767", "485820bdbe442431"],
    crc128Seed: ["54d6120ea2972e90", "f437a0341f29b72a"],
    crc256: ["8f30885c784d5704", "aa95376b16c7906a", "e826928cfaf93dc3", "20e8f54d1c16d7d8"],
  },
  {
    crc128: ["80973ea532b0f310", "a471829aa9c17dd9"],
    crc128Seed: ["c2ff3479394804ab", "6bf44f8606753636"],
    crc256: ["5184d2973e6dd827", "121b96369a332d9a", "5c25d3475ab69e50", "26d2961d62884168"],
  },
  {
    crc128: ["230d2b3e47f09830", "ec8624a821c1caf4"],
    crc128Seed: ["ea6ec411cdbf1cb1", "5f38ae82af364e27"],
    crc256: ["a519ef515ea7187c", "6bad5efa7ebae05f", "748abacb11a74a63", "a28eef963d1396eb"],
  },
  {
    crc128: ["7122413bdbc94035", "e7f90fae33bf7763"],
    crc128Seed: ["4b6bd0fb30b12387", "557359c0c44f48ca"],
    crc256: ["d5656c3d6bc5f0d", "983ff8e5e784da99", "628479671b445bf", "e179a1e27ce68f5d"],
  },
  {
    crc128: ["5ed12338f630ab76", "fab19fcb319116d"],
    crc128Seed: ["167f5f42b521724b", "c4aa56c409568d74"],
    crc256: ["75fff4b42f8e9778", "94218f94710c1ea3", "b7b05efb738b06a6", "83fff2deabf9cd3"],
  },
  {
    crc128: ["fca4e5bc9292788e", "cd509dc1facce41c"],
    crc128Seed: ["bbba575a59d82fe", "4e2e71c15b45d4d3"],
    crc256: ["5dc54582ead999c", "72612d1571963c6f", "30318a9d2d3d1829", "785dd00f4cc9c9a0"],
  },
  {
    crc128: ["967e970df9673d2a", "d465247cffa415c0"],
    crc128Seed: ["33a1df0ca1107722", "49fc2a10adce4a32"],
    crc256: ["c5707e079a284308", "573028266635dda6", "f786f5eee6127fa0", "b30d79cebfb51266"],
  },
  {
    crc128: ["815308a32a9b0daf", "efb2ab27bf6fd0bd"],
    crc128Seed: ["9f1ffc0986111118", "f9a3aa1778ea3985"],
    crc256: ["698fe54b2b93933b", "dacc2b28404d0f10", "815308a32a9b0daf", "efb2ab27bf6fd0bd"],
  },
];

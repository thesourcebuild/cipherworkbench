/**
 * The tools this family contributes, as eager metadata.
 *
 * One per CRC width — twenty-two sidebar entries covering all 113 named models. Splitting
 * by width rather than by model is what keeps the tool list navigable: `CRC-32` is a
 * thing people look for, `CRC-32/BASE91-D` is a thing they pick from a dropdown once
 * they are already there.
 *
 * Adler-32 used to be the sixth entry here, sharing this family's plumbing because it is
 * also a small integer over a byte stream. It moved to `@ocs/checksum` when that family
 * arrived: it is two modular sums rather than a polynomial division, and the two are a
 * category apart rather than two strengths of one thing.
 *
 * Free of any `@ocs/algos` import, so listing these costs nothing but the strings.
 * The model catalogue itself is reached only from `../definition.ts`.
 */

export interface CrcToolMeta {
  id: string;
  label: string;
  /** Which CRC width this tool covers. */
  width: number;
  /** The variant a fresh spec starts on, so it never means "one of thirty-one CRC-16s". */
  defaultModel: string;
  tags: readonly string[];
  summary: string;
}

/**
 * Every entry is `not-a-mac`, and the note says so in its own words rather than
 * repeating one sentence five times. This is the single most useful thing this family
 * can tell a user: a CRC will catch a flipped bit on a wire and will not notice a
 * deliberate change, because computing a matching CRC for altered data is arithmetic
 * anyone can do.
 */
export const CRC_TOOLS: readonly CrcToolMeta[] = [
  {
    id: "crc8",
    label: "CRC-8",
    width: 8,
    defaultModel: "CRC-8/SMBUS",
    tags: [
      "crc", "crc8", "crc-8", "checksum", "smbus", "1-wire", "dallas", "maxim", "aes", "atm hec",
      "autosar", "bluetooth", "ccitt", "cdma2000", "crc-8/aes", "crc-8/autosar",
      "crc-8/bluetooth", "crc-8/ccitt", "crc-8/cdma2000", "crc-8/darc", "crc-8/dvb-s2",
      "crc-8/ebu", "crc-8/gsm-a", "crc-8/gsm-b", "crc-8/hitag", "crc-8/i-432-1", "crc-8/i-code",
      "crc-8/itu", "crc-8/lte", "crc-8/maxim", "crc-8/maxim-dow", "crc-8/mifare-mad",
      "crc-8/nrsc-5", "crc-8/opensafety", "crc-8/rohc", "crc-8/sae-j1850", "crc-8/smbus",
      "crc-8/tech-3250", "crc-8/wcdma", "darc", "dow-crc", "dvb-s2", "ebu", "gsm-a", "gsm-b",
      "hitag", "i-432-1", "i-code", "itu", "lte", "maxim-dow", "mifare-mad", "nrsc-5",
      "opensafety", "rohc", "sae-j1850", "tech-3250", "wcdma",
    ],
    summary: "8-bit checksum — 13 named variants including SMBus, 1-Wire and Bluetooth.",
  },
  {
    id: "crc16",
    label: "CRC-16",
    width: 16,
    defaultModel: "CRC-16/ARC",
    tags: [
      "crc", "crc16", "crc-16", "checksum", "modbus", "ccitt", "kermit", "xmodem", "usb", "acorn",
      "arc", "aug-ccitt", "autosar", "bluetooth", "buypass", "ccit_zero", "ccitt-false",
      "ccitt-true", "cdma2000", "cms", "crc-16/acorn", "crc-16/arc", "crc-16/aug-ccitt",
      "crc-16/autosar", "crc-16/bluetooth", "crc-16/buypass", "crc-16/ccit_zero", "crc-16/ccitt",
      "crc-16/ccitt-false", "crc-16/ccitt-true", "crc-16/cdma2000", "crc-16/cms", "crc-16/darc",
      "crc-16/dds-110", "crc-16/dect-r", "crc-16/dect-x", "crc-16/dnp", "crc-16/en-13757",
      "crc-16/epc", "crc-16/epc-c1g2", "crc-16/genibus", "crc-16/gsm", "crc-16/i-code",
      "crc-16/ibm-3740", "crc-16/ibm-sdlc", "crc-16/iec-61158-2", "crc-16/iso-hdlc",
      "crc-16/iso-iec-14443-3-a", "crc-16/kermit", "crc-16/lha", "crc-16/lj1200", "crc-16/lte",
      "crc-16/m17", "crc-16/maxim", "crc-16/maxim-dow", "crc-16/mcrf4xx", "crc-16/modbus",
      "crc-16/nrsc-5", "crc-16/opensafety-a", "crc-16/opensafety-b", "crc-16/profibus",
      "crc-16/riello", "crc-16/spi-fujitsu", "crc-16/t10-dif", "crc-16/teledisk",
      "crc-16/tms37157", "crc-16/umts", "crc-16/usb", "crc-16/v-41-lsb", "crc-16/v-41-msb",
      "crc-16/verifone", "crc-16/x-25", "crc-16/xmodem", "crc-16/zmodem", "crc-a", "crc-b",
      "crc-ccitt", "crc-ibm", "darc", "dds-110", "dect-r", "dect-x", "dnp", "en-13757", "epc",
      "epc-c1g2", "genibus", "gsm", "i-code", "ibm-3740", "ibm-sdlc", "iec-61158-2", "iso-hdlc",
      "iso-iec-14443-3-a", "lha", "lj1200", "lte", "m17", "maxim", "maxim-dow", "mcrf4xx",
      "mifare", "nrsc-5", "opensafety-a", "opensafety-b", "profibus", "r-crc-16", "riello",
      "spi-fujitsu", "t10-dif", "teledisk", "tms37157", "umts", "v-41-lsb", "v-41-msb",
      "verifone", "x-25", "x-crc-16", "zmodem",
    ],
    summary: "16-bit checksum — 31 named variants including MODBUS, CCITT, XMODEM and USB.",
  },
  {
    id: "crc24",
    label: "CRC-24",
    width: 24,
    defaultModel: "CRC-24/OPENPGP",
    tags: [
      "crc", "crc24", "crc-24", "checksum", "openpgp", "pgp", "ble", "flexray", "lte",
      "crc-24/ble", "crc-24/flexray-a", "crc-24/flexray-b", "crc-24/interlaken", "crc-24/lte-a",
      "crc-24/lte-b", "crc-24/openpgp", "crc-24/os-9", "flexray-a", "flexray-b", "interlaken",
      "lte-a", "lte-b", "os-9", "pgp armor",
    ],
    summary: "24-bit checksum — OpenPGP's armor checksum, Bluetooth LE, FlexRay and LTE.",
  },
  {
    id: "crc32",
    label: "CRC-32",
    width: 32,
    defaultModel: "CRC-32/ISO-HDLC",
    tags: [
      "crc", "crc32", "crc-32", "crc32c", "castagnoli", "checksum", "zip", "gzip", "png",
      "ethernet", "aal5", "adccp", "aixm", "autosar", "b-crc-32", "base91-c", "base91-d", "bzip2",
      "cd-rom-edc", "cksum", "crc-32/aal5", "crc-32/adccp", "crc-32/aixm", "crc-32/autosar",
      "crc-32/base91-c", "crc-32/base91-d", "crc-32/bzip2", "crc-32/castagnoli",
      "crc-32/cd-rom-edc", "crc-32/cksum", "crc-32/dect-b", "crc-32/interlaken", "crc-32/iscsi",
      "crc-32/iso-hdlc", "crc-32/jamcrc", "crc-32/mef", "crc-32/mpeg-2", "crc-32/nvme",
      "crc-32/posix", "crc-32/v-42", "crc-32/xfer", "crc-32/xz", "crc-32c", "crc-32d", "crc-32q",
      "dect-b", "ext4", "interlaken", "iscsi", "iso-hdlc", "jamcrc", "mef", "mpeg-2", "nvme",
      "pkzip", "posix", "sctp", "v-42", "xfer", "xz",
    ],
    summary:
      "32-bit checksum — the one in gzip, PNG, ZIP and Ethernet, plus CRC-32C and 10 more.",
  },
  {
    id: "crc64",
    label: "CRC-64",
    width: 64,
    defaultModel: "CRC-64/XZ",
    tags: [
      "crc", "crc64", "crc-64", "checksum", "xz", "ecma", "redis", "go", "crc-64/ecma-182",
      "crc-64/go-ecma", "crc-64/go-iso", "crc-64/ms", "crc-64/nvme", "crc-64/redis", "crc-64/we",
      "crc-64/xz", "ecma-182", "go-ecma", "go-iso", "ms", "nvme", "we",
    ],
    summary: "64-bit checksum — the variants used by xz, Go's hash/crc64, and Redis.",
  },
  {
    id: "crc82",
    label: "CRC-82",
    width: 82,
    defaultModel: "CRC-82/DARC",
    tags: [
      "crc", "crc82", "crc-82", "darc", "82-bit", "widest", "checksum", "crc-82/darc",
    ],
    summary: "82-bit checksum -- CRC-82/DARC, the widest CRC anyone has published.",
  },
  {
    id: "crc3",
    label: "CRC-3",
    width: 3,
    defaultModel: "CRC-3/ROHC",
    tags: [
      "crc", "crc3", "crc-3", "rohc", "gsm", "checksum", "crc-3/gsm", "crc-3/rohc",
    ],
    summary: "3-bit checksum -- two variants, from ROHC header compression and GSM.",
  },
  {
    id: "crc4",
    label: "CRC-4",
    width: 4,
    defaultModel: "CRC-4/G-704",
    tags: [
      "crc", "crc4", "crc-4", "g.704", "itu", "interlaken", "checksum", "crc-4/g-704",
      "crc-4/interlaken", "g-704",
    ],
    summary: "4-bit checksum -- ITU-T G.704 telecom framing and Interlaken.",
  },
  {
    id: "crc5",
    label: "CRC-5",
    width: 5,
    defaultModel: "CRC-5/USB",
    tags: [
      "crc", "crc5", "crc-5", "usb", "epc", "rfid", "g.704", "checksum", "crc-5/epc-c1g2",
      "crc-5/g-704", "crc-5/usb", "epc-c1g2", "g-704",
    ],
    summary: "5-bit checksum -- USB token packets, EPC Gen2 RFID and G.704.",
  },
  {
    id: "crc6",
    label: "CRC-6",
    width: 6,
    defaultModel: "CRC-6/GSM",
    tags: [
      "crc", "crc6", "crc-6", "darc", "gsm", "cdma2000", "g.704", "checksum", "cdma2000-a",
      "cdma2000-b", "crc-6/cdma2000-a", "crc-6/cdma2000-b", "crc-6/darc", "crc-6/g-704",
      "crc-6/gsm", "g-704",
    ],
    summary: "6-bit checksum -- five variants from DARC, GSM, CDMA2000 and G.704.",
  },
  {
    id: "crc7",
    label: "CRC-7",
    width: 7,
    defaultModel: "CRC-7/MMC",
    tags: [
      "crc", "crc7", "crc-7", "mmc", "sd", "sdcard", "rohc", "umts", "checksum", "crc-7/mmc",
      "crc-7/rohc", "crc-7/umts",
    ],
    summary: "7-bit checksum -- SD/MMC card commands, ROHC and UMTS.",
  },
  {
    id: "crc10",
    label: "CRC-10",
    width: 10,
    defaultModel: "CRC-10/ATM",
    tags: [
      "crc", "crc10", "crc-10", "atm", "cdma2000", "gsm", "aal", "checksum", "crc-10/atm",
      "crc-10/cdma2000", "crc-10/gsm",
    ],
    summary: "10-bit checksum -- three variants, from ATM AAL3/4, CDMA2000 and GSM.",
  },
  {
    id: "crc11",
    label: "CRC-11",
    width: 11,
    defaultModel: "CRC-11/FLEXRAY",
    tags: [
      "crc", "crc11", "crc-11", "flexray", "umts", "automotive", "checksum", "crc-11/flexray",
      "crc-11/umts",
    ],
    summary: "11-bit checksum -- FlexRay's automotive bus and UMTS.",
  },
  {
    id: "crc12",
    label: "CRC-12",
    width: 12,
    defaultModel: "CRC-12/DECT",
    tags: [
      "crc", "crc12", "crc-12", "dect", "cdma2000", "gsm", "umts", "x-crc", "checksum",
      "crc-12/cdma2000", "crc-12/dect", "crc-12/gsm", "crc-12/umts",
    ],
    summary: "12-bit checksum -- four variants, from DECT, CDMA2000, GSM and UMTS.",
  },
  {
    id: "crc13",
    label: "CRC-13",
    width: 13,
    defaultModel: "CRC-13/BBC",
    tags: [
      "crc", "crc13", "crc-13", "bbc", "teleswitch", "checksum", "crc-13/bbc",
    ],
    summary: "13-bit checksum -- one variant, CRC-13/BBC.",
  },
  {
    id: "crc14",
    label: "CRC-14",
    width: 14,
    defaultModel: "CRC-14/DARC",
    tags: [
      "crc", "crc14", "crc-14", "darc", "gsm", "radio", "checksum", "crc-14/darc", "crc-14/gsm",
    ],
    summary: "14-bit checksum -- DARC radio data and GSM.",
  },
  {
    id: "crc15",
    label: "CRC-15",
    width: 15,
    defaultModel: "CRC-15/CAN",
    tags: [
      "crc", "crc15", "crc-15", "can", "can bus", "mpt1327", "automotive", "checksum",
      "crc-15/can", "crc-15/mpt1327",
    ],
    summary: "15-bit checksum -- CRC-15/CAN, on every classic CAN 2.0 frame, and MPT1327.",
  },
  {
    id: "crc17",
    label: "CRC-17",
    width: 17,
    defaultModel: "CRC-17/CAN-FD",
    tags: [
      "crc", "crc17", "crc-17", "can-fd", "canfd", "can", "automotive", "checksum",
      "crc-17/can-fd",
    ],
    summary: "17-bit checksum -- CRC-17/CAN-FD, for CAN FD frames up to 16 data bytes.",
  },
  {
    id: "crc21",
    label: "CRC-21",
    width: 21,
    defaultModel: "CRC-21/CAN-FD",
    tags: [
      "crc", "crc21", "crc-21", "can-fd", "canfd", "can", "automotive", "checksum",
      "crc-21/can-fd",
    ],
    summary: "21-bit checksum -- CRC-21/CAN-FD, for CAN FD frames above 16 data bytes.",
  },
  {
    id: "crc30",
    label: "CRC-30",
    width: 30,
    defaultModel: "CRC-30/CDMA",
    tags: [
      "crc", "crc30", "crc-30", "cdma", "cdma2000", "mobile", "checksum", "crc-30/cdma",
    ],
    summary: "30-bit checksum -- one variant, CRC-30/CDMA.",
  },
  {
    id: "crc31",
    label: "CRC-31",
    width: 31,
    defaultModel: "CRC-31/PHILIPS",
    tags: [
      "crc", "crc31", "crc-31", "philips", "31-bit", "checksum", "crc-31/philips",
    ],
    summary: "31-bit checksum -- one variant, CRC-31/PHILIPS.",
  },
  {
    id: "crc40",
    label: "CRC-40",
    width: 40,
    defaultModel: "CRC-40/GSM",
    tags: [
      "crc", "crc40", "crc-40", "gsm", "mobile", "checksum", "crc-40/gsm",
    ],
    summary: "40-bit checksum -- one variant, CRC-40/GSM.",
  },
];

const BY_ID = new Map(CRC_TOOLS.map((t) => [t.id, t]));

export function getCrcTool(id: string): CrcToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireCrcTool(id: string): CrcToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown CRC tool: ${id}`);
  return meta;
}

export const CRC_TOOL_IDS: readonly string[] = CRC_TOOLS.map((t) => t.id);

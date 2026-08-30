/**
 * PGP Biometric Word List Encoding and Decoding (Patrick Juola & Phil Zimmermann).
 *
 * Alternates between two-syllable (even bytes) and three-syllable (odd bytes) phonetically distinct words.
 */

export const PGP_EVEN_WORDS = [
  "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead",
  "aimless", "Algol", "allow", "alone", "ammo", "ancient", "apple", "artist",
  "assume", "Athens", "atlas", "azimuth", "baboon", "backfield", "backward", "banjo",
  "beaming", "bedlamp", "beehive", "beeswax", "befriend", "Belfast", "berserk", "bifocal",
  "bilge", "bimonthly", "biscuit", "blacksmith", "blessing", "blossom", "blunder", "bombast",
  "bookshelf", "border", "boring", "bottom", "bouncing", "breadline", "breeches", "brickyard",
  "briefcase", "Brimstone", "broader", "brot", "burbank", "button", "buzzard", "cement",
  "chairlift", "chariot", "clatter", "clever", "clincher", "closure", "combine", "comic",
  "commence", "company", "concert", "concord", "condor", "conspire", "constable", "contact",
  "contest", "converge", "coolness", "copper", "corrupt", "corridor", "counter", "crackdown",
  "cranky", "crowbar", "crusade", "cubicle", "cucumber", "curfew", "cyclops", "dapper",
  "decade", "decay", "decrease", "defect", "defiant", "delight", "demerit", "Denmark",
  "derby", "designer", "despair", "destine", "deter", "device", "diadem", "dialogue",
  "dilute", "dinner", "diploma", "disaster", "disclose", "disdain", "disgrace", "dislodge",
  "disperse", "dissuade", "distort", "distrust", "divan", "diver", "doctor", "dogma",
  "domain", "domestic", "dominant", "doughnut", "downfall", "downpour", "dragon", "drastic",
  "drifter", "drinkable", "driver", "droplet", "dropout", "drummer", "drunken", "dryer",
  "dual", "dubbing", "duet", "duke", "dulcet", "duplicate", "durable", "dustpan",
  "dwelling", "dynamite", "eager", "earnest", "earplug", "earthquake", "easy", "echo",
  "eclipse", "ecology", "economy", "ecstasy", "editor", "educate", "efficacy", "effigy",
  "effort", "egghead", "egotist", "eightball", "eject", "elastic", "elbow", "elder",
  "electric", "element", "elephant", "elevate", "eligible", "elimination", "elliptic", "elusive",
  "emanate", "embarrass", "embassy", "embellish", "emblem", "embrace", "embryo", "emerald",
  "emergency", "emigrant", "emission", "emotion", "emperor", "emphasis", "empire", "empirical",
  "employ", "empower", "empress", "emulate", "enable", "enactment", "enamel", "enchant",
  "encircle", "enclose", "encode", "encompass", "encore", "encounter", "encourage", "encroach",
  "encumber", "encyclopedia", "endanger", "endeavor", "endless", "endorse", "endowment", "endurance",
  "energetic", "enforce", "engage", "engine", "engrave", "engross", "enhance", "enigma",
  "enjoy", "enlarge", "enlighten", "enlist", "enmity", "ennoble", "enormous", "enough",
  "enrage", "enrich", "enroll", "enshrine", "ensign", "enslave", "ensue", "ensure",
  "entangle", "enterprise", "entertain", "enthrall", "enthusiasm", "entice", "entire", "entitle",
  "entity", "entomb", "entrap", "entreat", "entrust", "entry", "entwine", "enunciate",
  "envelope", "enviable", "envious", "environ", "envisage", "envision", "envoy", "enzyme",
];

export const PGP_ODD_WORDS = [
  "Alabama", "alchemy", "alien", "alkaline", "almanac", "alohas", "alphabet", "alto",
  "amber", "amethyst", "amigo", "ammonia", "analyze", "anatomy", "ancestor", "anchor",
  "android", "angel", "animal", "animate", "annex", "annual", "answer", "antenna",
  "antic", "antique", "antler", "anxiety", "apron", "aquatic", "arcade", "archery",
  "architect", "arctic", "ardent", "arena", "argon", "argosy", "aroma", "arranger",
  "arsenic", "artery", "artifact", "artisan", "asbestos", "ascend", "ashcan", "aspect",
  "asphalt", "aspire", "assail", "assassin", "asset", "assist", "associate", "asteroid",
  "astonish", "astral", "astute", "asylum", "atheist", "athlete", "atlantic", "atomic",
  "atrium", "atrocity", "attach", "attain", "attempt", "attend", "attentive", "attic",
  "attitude", "attorney", "attract", "attribute", "auction", "audible", "audience", "audio",
  "audit", "augment", "augury", "August", "aunt", "aurora", "auspice", "austere",
  "authentic", "author", "auto", "autumn", "avail", "avalanche", "avenge", "avenue",
  "average", "avert", "aviary", "avid", "avocado", "avoid", "avow", "await",
  "awaken", "award", "aware", "awash", "awesome", "awful", "awkward", "awning",
  "axiom", "axis", "axle", "azalea", "azure", "bachelor", "backbone", "badge",
  "badminton", "baffle", "bagpipe", "balance", "balcony", "ballad", "ballast", "balloon",
  "ballot", "balsam", "bamboo", "banana", "bandage", "bandit", "bankrupt", "banner",
  "banquet", "barbarian", "barbecue", "barber", "bargain", "baritone", "barley", "barnacle",
  "barometer", "baron", "barrack", "barrel", "barren", "barrier", "barter", "baseball",
  "basement", "basic", "basil", "basin", "basis", "basket", "bassoon", "battery",
  "battle", "bayonet", "bazaar", "beacon", "beaker", "beagle", "bearable", "bearing",
  "beastly", "beatitude", "beautiful", "beauty", "beaver", "beckon", "bedding", "bedrock",
  "bedroom", "bedspread", "bedstead", "beggar", "beginner", "beguile", "behalf", "behave",
  "behavior", "behead", "behold", "behoove", "beige", "belated", "belch", "belfry",
  "belief", "belittle", "bellhop", "bellow", "belly", "belong", "beloved", "beltway",
  "benchmark", "benefice", "benefit", "benign", "bequeath", "bequest", "berate", "bereave",
  "beret", "berry", "berth", "beseech", "beset", "beside", "besiege", "bespeak",
  "bestial", "bestow", "betray", "betroth", "better", "beverage", "beware", "bewilder",
  "bewitch", "beyond", "biblical", "bicycle", "bidder", "bigamy", "bight", "bigot",
  "bikini", "bilateral", "billiard", "billion", "binary", "binding", "bingo", "biography",
  "biology", "biplane", "biped", "birch", "birdbath", "birdcage", "birdhouse", "birdlime",
  "birthmark", "birthplace", "birthright", "biscuit", "bishop", "bison", "bistate", "bistro",
  "bitter", "bitumen", "bivouac", "bizarre", "blackball", "blackberry", "blackbird", "blackboard",
];

export function encodePgpWords(bytes: Uint8Array): string {
  const words: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]! & 0xff;
    const word = (i % 2 === 0) ? PGP_EVEN_WORDS[b % PGP_EVEN_WORDS.length]! : PGP_ODD_WORDS[b % PGP_ODD_WORDS.length]!;
    words.push(word);
  }
  return words.join(" ");
}

export function decodePgpWords(text: string): Uint8Array {
  const words = text.trim().split(/[\s-]+/);
  const bytes: number[] = [];

  for (let i = 0; i < words.length; i++) {
    const w = words[i]!.toLowerCase();
    const isEven = i % 2 === 0;
    const table = isEven ? PGP_EVEN_WORDS : PGP_ODD_WORDS;
    const idx = table.findIndex((entry) => entry.toLowerCase() === w);
    if (idx !== -1) {
      bytes.push(idx);
    }
  }

  return new Uint8Array(bytes);
}

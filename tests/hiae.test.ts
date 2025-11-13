import { expect, test } from "bun:test";
import { decrypt, encrypt, mac, stream } from "../src/hiae.js";

// Helper function to convert hex string to Uint8Array
function hex2bytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Helper function to convert Uint8Array to hex string
function bytes2hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const testVectors = [
  {
    name: "Test Vector 1 - Empty plaintext, no AD",
    key: "4b7a9c3ef8d2165a0b3e5f8c9d4a7b1e2c5f8a9d3b6e4c7f0a1d2e5b8c9f4a7d",
    nonce: "a5b8c2d9e3f4a7b1c8d5e9f2a3b6c7d8",
    ad: "",
    msg: "",
    ct: "",
    tag: "a25049aa37deea054de461d10ce7840b",
  },
  {
    name: "Test Vector 2 - Single block plaintext, no AD",
    key: "2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e",
    nonce: "7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a",
    ad: "",
    msg: "55f00fcc339669aa55f00fcc339669aa",
    ct: "af9bd1865daa6fc351652589abf70bff",
    tag: "ed9e2edc8241c3184fc08972bd8e9952",
  },
  {
    name: "Test Vector 3 - Empty plaintext with AD",
    key: "9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e",
    nonce: "3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d",
    ad: "394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748",
    msg: "",
    ct: "",
    tag: "7e19c04f68f5af633bf67529cfb5e5f4",
  },
  {
    name: "Test Vector 4 - Rate-aligned plaintext (256 bytes)",
    key: "6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d",
    nonce: "9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f",
    ad: "",
    msg: "ffffffffffffffffffffffffffffffff".repeat(16),
    ct: "cf9f118ccc3ae98998ddaae1a5d1f9a169e4ca3e732baf7178cdd9a3530571668fe403e77111eac3da34bf2f25719cea09445cc58197b1c6ac490626724e7372707cfb60cdba8262f0e33a1ef8adda1f2e390a80c58e5c055d9be9bbccdc06adaf74f1dcaa372204bf42e5e0e0ac59437a353978298837023f79fac6daa1fe8f6bcaaaf060ae2e37ed7b7da0577a76435f0403b8e277b6bc2ea99682f2d0d57777fec6d901e0d8fc7cf46bb97336812a2d8cfd39053993288cce2c077fce0c6c00e99cf919281b261acf86b058164f101d9c24e8f40b4fa0ed60955eeeb4e33ff1087519c13db8e287199a7df7e94b0d368da9ccf3d2ecebfa46f860348f8e3c",
    tag: "4f42c3042cba3973153673156309dd69",
  },
  {
    name: "Test Vector 5 - Rate + 1 byte plaintext",
    key: "3e9d6c5b4a8f7e2d1c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d",
    nonce: "6f2e8a5c9b3d7f1e4a8c5b9d3f7e2a6c",
    ad: "6778899aabbccddeef00112233445566",
    msg: `${"cc339669aa55f00f".repeat(32)}cc`,
    ct: "522e4cd9b0881809d80e149bb4ed8b8add70b7257afca6c2bc38e4da11e290cfcabd9dd1d4ed8c514482f444f903e42ec21a7a605ee37f95a504ec667fabec4066eb4521cdaf9c4eb7b62d659ab0a9363b145f1120c1b2e589ab9cb893d01be0d22182fc7de4932f1e8652b50e4a0d48c49a8a1232b201e2e535cd95c15cf0ee389b75e372653579c72c4dd1906fd81c2b9fc2483fab8b4df5a09d59753b5bd41334be2e5085e349b6e5aac0c555a0a83e94eab974052131f8d451c9d85389a36126f93464e6f93119c6b1bf15b4c0a9e6c9beb52e82c846c472f87c15ac49e99d59248ba7e6b97ca04327769d6b8c1f751d95dba709fb335183c21476836ea1ab",
    tag: "61bac11505dd8bbf55e7fbb7489de7b0",
  },
  {
    name: "Test Vector 6 - Rate - 1 byte plaintext",
    key: "8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f",
    nonce: "4d8b2f6a9c3e7f5d1b8a4c6e9f3d5b7a",
    ad: "",
    msg: "00".repeat(255),
    ct: "2ba49be54eb675efe446fd597721d4cdca6e01f1a51728a859d8f206d13cdb08ba4f0fe78fbbd6885964ed54e9beceed1ff306642c4761e67efa7a2620e5712815b5e9f066b42e879cd62e7adc2821e508311b88a6ee14bedcbac7ce339994c009bbbadf9444748e4ab9a91acbbc7301742dab74aa1be6847ad8e9f08c170359b87e0ccd480812aaaf847aff03c2e8581c55848c2b50f6c6608540fe82627a2c0f5ee37fbe9cdeab5f6c9799702bd3032bf733e2108d03247cd20edaa2c322e5bf086bfecc4ac97b61096f016c57d5d01c24d398cefd5ae8131c1f51f172ce9c6d3b8395d396dcbd70b4af790018796b31f0b0ad6198f86e5e1f26e9258492",
    tag: "221dd1b69afb4e0c149e0a058e471a4a",
  },
  {
    name: "Test Vector 7 - Medium plaintext with AD",
    key: "5d9c3b7a8f2e6d4c1b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c",
    nonce: "8c5a7d3f9b1e6c4a2f8d5b9e3c7a1f6d",
    ad: "95a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4",
    msg: "32e14453e7a776781d4c4e2c3b23bca2441ee4213bc3df25021b5106c22c98e8a7b310142252c8dcff70a91d55cdc9103c1eccd9b5309ef21793a664e0d4b63c83530dcd1a6ad0feda6ff19153e9ee620325c1cb979d7b32e54f41da3af1c169a24c47c1f6673e115f0cb73e8c507f15eedf155261962f2d175c9ba3832f4933fb330d28ad6aae787f12788706f45c92e72aea146959d2d4fa01869f7d072a7bf43b2e75265e1a000dde451b64658919e93143d2781955fb4ca2a38076ac9eb49adc2b92b05f0ec7",
    ct: "1d8d56867870574d1c4ac114620c6a2abb44680fe321dd116601e2c92540f85a11c41dcac9814397b8f37b812cd52c932db6ecbaa247c3e14f228bd7923345702fc43ad1eb1b8086e2c3c57bb602971c29772a35dfb1c45c66f81633e67fdc8d8005457ddbe4179312abab981049eb0a0a555b9fa01378878d7349111e2446fde89ce64022d032cbf0cf2672e00d7999ed8b631c1b9bee547cbe464673464a4b80e8f72ad2b91a40fdcee5357980c090b34ab5e732e2a7df7613131ee42e42ec6ae9b05ac5683ebe",
    tag: "e93686b266c481196d44536eb51b5f2d",
  },
  {
    name: "Test Vector 8 - Single byte plaintext",
    key: "7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
    nonce: "2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a",
    ad: "",
    msg: "ff",
    ct: "21",
    tag: "3cf9020bd1cc59cc5f2f6ce19f7cbf68",
  },
  {
    name: "Test Vector 9 - Two blocks plaintext",
    key: "4c8b7a9f3e5d2c6b1a8f9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b",
    nonce: "7e3c9a5f1d8b4e6c2a9f5d7b3e8c1a4f",
    ad: "c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2",
    msg: "aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669",
    ct: "c2e199ac8c23ce6e3778e7fd0b4f8f752badd4b67be0cdc3f6c98ae5f6fb0d25",
    tag: "7aea3fbce699ceb1d0737e0483217745",
  },
  {
    name: "Test Vector 10 - All zeros plaintext",
    key: "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
    nonce: "5f9d3b7e2c8a4f6d1b9e5c7a3d8f2b6e",
    ad: "daebfc0d1e2f405162738495a6b7c8d9",
    msg: "00".repeat(128),
    ct: "fc7f1142f681399099c5008980e7342065b4e62a9b9cb301bdf441d3282b6aa93bd7cd735ef77755b4109f86b7c090838e7b05f08ef4947946155a03ff483095152ef3dec8bdddae3990d00d41d5ee6c90dcf65dbed4b7ebbe9bb4ef096e1238d388bf15faacdb7a68be19dddc8a5b74216f4442bfa32d1dfccdc9c4020baec9",
    tag: "ad0b841c3d145a6ee86dc7b67338f113",
  },
];

// Test encryption and decryption
testVectors.forEach((tv) => {
  test(`encrypt: ${tv.name}`, () => {
    const key = hex2bytes(tv.key);
    const nonce = hex2bytes(tv.nonce);
    const ad = hex2bytes(tv.ad);
    const msg = hex2bytes(tv.msg);

    const { ciphertext, tag } = encrypt(msg, ad, key, nonce);

    expect(bytes2hex(ciphertext)).toBe(tv.ct);
    expect(bytes2hex(tag)).toBe(tv.tag);
  });

  test(`decrypt: ${tv.name}`, () => {
    const key = hex2bytes(tv.key);
    const nonce = hex2bytes(tv.nonce);
    const ad = hex2bytes(tv.ad);
    const ct = hex2bytes(tv.ct);
    const tag = hex2bytes(tv.tag);
    const expectedMsg = hex2bytes(tv.msg);

    const msg = decrypt(ct, tag, ad, key, nonce);

    expect(msg).not.toBeNull();
    expect(msg).toEqual(expectedMsg);
  });
});

// Test invalid tag
test("decrypt with invalid tag", () => {
  const tv = testVectors[1]; // Use test vector 2
  const key = hex2bytes(tv.key);
  const nonce = hex2bytes(tv.nonce);
  const ad = hex2bytes(tv.ad);
  const ct = hex2bytes(tv.ct);
  const tag = hex2bytes(tv.tag);

  // Corrupt the tag
  tag[0] ^= 0x01;

  const msg = decrypt(ct, tag, ad, key, nonce);
  expect(msg).toBeNull();
});

// Test stream cipher mode
test("stream cipher mode", () => {
  const key = hex2bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  const nonce = hex2bytes("00112233445566778899aabbccddeeff");

  const keystream = stream(32, key, nonce);
  expect(keystream.length).toBe(32);

  // Stream with zero length
  const emptyStream = stream(0, key, nonce);
  expect(emptyStream.length).toBe(0);
});

// Test MAC mode
test("MAC mode", () => {
  const key = hex2bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  const nonce = hex2bytes("00112233445566778899aabbccddeeff");
  const data = new TextEncoder().encode("Hello, World!");

  const tag1 = mac(data, key, nonce);
  expect(tag1.length).toBe(16);

  // Same data should produce same tag
  const tag2 = mac(data, key, nonce);
  expect(tag1).toEqual(tag2);

  // Different data should produce different tag
  const data2 = new TextEncoder().encode("Hello, World");
  const tag3 = mac(data2, key, nonce);
  expect(tag1).not.toEqual(tag3);
});

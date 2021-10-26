using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using static Loader.Constants;

namespace Loader
{
    /// <summary>
    /// Utility methods to decrypt Girls' Frontline (少女前线) metadata and binary images.
    ///
    /// <para />
    /// If you want to follow along, offsets in this project refer to <c>arm64-v8a</c> binary <c>libtprt.so</c>
    /// from EN client v<c>2.0702_362</c>, app id <c>com.sunborn.girlsfrontline.en</c>.
    ///
    /// <para />
    /// Metadata header (first <c>0x110</c> bytes) is encrypted in a convoluted way, making use of some Rijndael (AES) constants,
    /// and many bitwise operations.
    ///
    /// <para />
    /// Metadata body decryption (everything after byte <c>0x110</c>) is much simpler: it's just XOR-encrypted.
    /// Finding the 8-byte XOR key, though, was much less simple.
    ///
    /// <para />
    /// Sections <c>.rodata</c> and <c>.text</c> in IL2CPP binary <c>libil2cpp.so</c> are XOR-encrypted in stripes,
    /// <a href="https://katyscode.wordpress.com/2021/01/15/reverse-engineering-adventures-league-of-legends-wild-rift-il2cpp/">something we are quite familiar with</a>.
    ///
    /// <para />
    /// Methods in this class are subdivided to try to have a one-to-one mapping with subroutines in the assembly.
    ///
    /// <para />
    /// Tested with the following Android clients (EN, JP, KR, and TW), both ARM and ARM64:
    /// <list type="bullet">
    ///     <item>
    ///         <description><c>com.sunborn.girlsfrontline.en</c> — v<c>2.0702_362</c></description>
    ///     </item>
    ///     <item>
    ///         <description><c>com.sunborn.girlsfrontline.jp</c> — v<c>2.0701_206</c></description>
    ///     </item>
    ///     <item>
    ///         <description><c>kr.txwy.and.snqx</c> — v<c>2.0801_300</c></description>
    ///     </item>
    ///     <item>
    ///         <description><c>tw.txwy.and.snqx</c> — v<c>2.0801_274</c></description>
    ///     </item>
    /// </list>
    /// </summary>
    public static class Utils
    {
        /// <summary>
        /// Extracts the <c>s</c>-th byte from dword <c>n</c>, counting from the LSB.
        /// <para />
        /// Example for dword <c>0x0A0B0C0D</c> at address <c>a</c>:
        /// <code>
        ///  DWORD           RAM
        ///  +--+--+--+--+
        ///  |0A|0B|0C|0D|   |  |
        ///  +-++-++-++-++   |..|
        ///    |  |  |  |    +--+
        ///    |  |  |  +--->|0D| a   --> BYTE 0 / LOBYTE
        ///    |  |  |       +--+
        ///    |  |  +------>|0C| a+1 --> BYTE 1
        ///    |  |          +--+
        ///    |  +--------->|0B| a+2 --> BYTE 2
        ///    |             +--+
        ///    +------------>|0A| a+3 --> BYTE 3 / HIBYTE
        ///                  +--+
        ///                  |..|
        ///                  |  |
        /// </code>
        /// </summary>
        /// <param name="n">the number from which to extract the <c>s</c>-th byte</param>
        /// <param name="s">the byte number to extract from <c>n</c></param>
        /// <returns>the <c>s</c>-th byte of <c>n</c>, counting from the LSB</returns>
        public static byte ByteN(uint n, byte s)
        {
            return (byte) ((n >> (8 * s)) & 0xff);
        }

        /// <summary>
        /// Extracts the low byte (byte 0) from dword <c>n</c>, counting from the LSB
        /// </summary>
        /// <param name="n">the number from which to extract the low byte (byte 0)</param>
        /// <returns>the low byte (byte 0) of <c>n</c>, counting from the LSB</returns>
        /// <seealso cref="ByteN"/>
        public static byte LoByte(uint n)
        {
            return ByteN(n, 0);
        }

        /// <summary>
        /// Extracts byte 1 from dword <c>n</c>, counting from the LSB
        /// </summary>
        /// <param name="n">the number from which to extract byte 1</param>
        /// <returns>byte 1 of <c>n</c>, counting from the LSB</returns>
        /// <seealso cref="ByteN"/>
        public static byte Byte1(uint n)
        {
            return ByteN(n, 1);
        }

        /// <summary>
        /// Extracts byte 2 from dword <c>n</c>, counting from the LSB
        /// </summary>
        /// <param name="n">the number from which to extract byte 2</param>
        /// <returns>byte 2 of <c>n</c>, counting from the LSB</returns>
        /// <seealso cref="ByteN"/>
        public static byte Byte2(uint n)
        {
            return ByteN(n, 2);
        }

        /// <summary>
        /// Extracts the high byte (byte 3) from dword <c>n</c>, counting from the LSB
        /// </summary>
        /// <param name="n">the number from which to extract the high byte (byte 3)</param>
        /// <returns>the high byte (byte 3) of <c>n</c>, counting from the LSB</returns>
        /// <seealso cref="ByteN"/>
        public static byte HiByte(uint n)
        {
            return ByteN(n, 3);
        }

        /// <summary>
        /// Converts a dword to an array of 4 bytes, LSB first
        /// </summary>
        /// <param name="n">the dword to convert</param>
        /// <returns>an array with the 4 bytes in dword <c>n</c>, LSB first</returns>
        /// <seealso cref="ByteN"/>
        public static byte[] DWordToByteArray(uint n)
        {
            return new[] {LoByte(n), Byte1(n), Byte2(n), HiByte(n)};
        }

        /// <summary>
        /// Pretty prints a byte array
        /// </summary>
        /// <param name="buffer">the byte array to print</param>
        public static void PrintBuffer(byte[] buffer)
        {
            string[] lines = Regex.Split(BitConverter.ToString(buffer).Replace("-", " "), "(.{1,48})")
                                  .Where(s => !string.IsNullOrWhiteSpace(s))
                                  .ToArray();

            string header = "      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F";
            string body = String.Join("\n", lines.Select((line, i) => $"{(i * 16):X4} {line}"));

            Debug.WriteLine($"{header}\n{body}\n");
        }

        /// <summary>
        /// Pretty prints a dword array, converting it to a byte array first
        /// </summary>
        /// <param name="buffer">the dword array to print</param>
        /// <seealso cref="DWordToByteArray"/>
        /// <seealso cref="PrintBuffer(byte[])"/>
        public static void PrintBuffer(uint[] buffer)
        {
            PrintBuffer(buffer.SelectMany(DWordToByteArray).ToArray());
        }

        /// <summary>
        /// XORs every byte in <c>bytes</c> with <c>xorKey</c>
        /// </summary>
        /// <param name="bytes">the input byte array</param>
        /// <param name="xorKey">the byte to XOR every byte in <c>bytes</c> with</param>
        /// <returns>a new byte array obtained by XOR-ing every byte in <c>bytes</c> with <c>xorKey</c></returns>
        public static byte[] XorBytes(byte[] bytes, byte xorKey)
        {
            return bytes.Select(b => (byte) (b ^ xorKey)).ToArray();
        }

        /// <summary>
        /// Finds the most common byte and its number of occurrences in <c>bytes</c>
        /// </summary>
        /// <param name="bytes">the input byte array</param>
        /// <returns>the most common byte and its number of occurrences in <c>bytes</c></returns>
        public static KeyValuePair<byte, int> MostCommonByteWithCount(byte[] bytes)
        {
            Dictionary<byte, int> bytesDictionary = bytes.GroupBy(b => b).ToDictionary(b => b.Key, b => b.Count());
            List<KeyValuePair<byte, int>> bytesFrequencyList = bytesDictionary.ToList();
            bytesFrequencyList.Sort((a, b) => b.Value - a.Value);
            KeyValuePair<byte, int> mostCommonByteWithCount = bytesFrequencyList.First();
            return mostCommonByteWithCount;
        }

        /// <summary>
        /// Decrypts a 16-byte piece of metadata header.
        /// <para />
        /// Offset: <c>0xD3E88</c>.
        /// </summary>
        /// <param name="input">the array of 16 bytes to decrypt</param>
        /// <param name="key">the decryption key</param>
        /// <returns>the decrypted piece of metadata header</returns>
        private static byte[] DecryptInnerMetadataHeaderDWord(byte[] input, uint[] key)
        {
            uint MapInputToKey(int i) => ((uint) input[i] << 24 | (uint) input[i + 1] << 16 | (uint) input[i + 2] << 8 | input[i + 3]) ^ key[i / 4];

            uint[] keys = new uint[] {0, 0, 0, 0}.Concat(Enumerable.Range(0, 4)
                                                                   .Select(i => i * 4)
                                                                   .Select(MapInputToKey))
                                                 .ToArray();

            uint MixKeys(int i, int j) => RijndaelTd0[HiByte(keys[i % 4 + j * 4])] ^
                                          RijndaelTd1[Byte2(keys[(i - 1) % 4 + j * 4])] ^
                                          RijndaelTd2[Byte1(keys[(i - 2) % 4 + j * 4])] ^
                                          RijndaelTd3[LoByte(keys[(i - 3) % 4 + j * 4])] ^
                                          key[i];


            for (int i = 4; i < 44; i += 8)
            {
                for (int j = 0; j < 8; ++j)
                {
                    keys[j] = MixKeys(i + j, j / 4 ^ 1);
                }
            }

            // i like me some functions inside functions that take functions as arguments; sorry about that
            byte MapKeyToOutput(Func<uint, byte> func, int i, int j) => func(RijndaelTd4[func(keys[(i + (4 - j)) % 4])] ^ key[40 + i]);

            byte[] output = new byte[16];
            for (int i = 0; i < 4; ++i)
            {
                foreach (var (j, func) in new (int, Func<uint, byte>)[] {(0, HiByte), (1, Byte2), (2, Byte1), (3, LoByte)})
                {
                    output[i * 4 + j] = MapKeyToOutput(func, i, j);
                }
            }

            return output;
        }

        /// <summary>
        /// Decrypts bytes <c>0x8</c> - <c>0x108</c> of metadata header.
        /// <para />
        /// Offset: <c>0xD4294</c> (part of).
        /// </summary>
        /// <param name="input">bytes <c>0x8</c> - <c>0x108</c> of metadata header</param>
        /// <param name="key">the decryption key</param>
        /// <param name="firstBytesOfLastPassKey">the first bytes of the last pass XOR key</param>
        /// <returns>the decrypted <c>0x8</c> - <c>0x108</c> part of metadata header</returns>
        private static byte[] DecryptInnerMetadataHeader(byte[] input, uint[] key, byte[] firstBytesOfLastPassKey)
        {
            // last pass XOR key from byte 16th onwards is... the input array :o
            byte[] xorKey = firstBytesOfLastPassKey.Take(16).Concat(input).ToArray();

            byte[] decrypted = new byte[input.Length];
            for (int i = 0; i < input.Length; i += 16)
            {
                int size = Math.Min(16, input.Length - i);
                byte[] dword = DecryptInnerMetadataHeaderDWord(input.Skip(i).Take(16).ToArray(), key).Take(size).ToArray();

                for (int j = 0; j < size; ++j)
                {
                    decrypted[i + j] = (byte) (dword[j] ^ xorKey[i + j]);
                }
            }

            return decrypted;
        }

        /// <summary>
        /// Decrypts metadata header.
        /// <para />
        /// Offset: <c>0xC5B48</c> (part of).
        /// </summary>
        /// <param name="metadata">the input metadata</param>
        /// <param name="key">the decryption key</param>
        /// <param name="lastPassHeaderKey">the last pass XOR key</param>
        /// <param name="headerLastBytesKey">the XOR key for the last 8 bytes</param>
        /// <returns>the whole decrypted metadata header</returns>
        public static byte[] DecryptMetadataHeader(byte[] metadata, uint[] key, byte[] lastPassHeaderKey, byte headerLastBytesKey)
        {
            // first 8 bytes of metadata header are hardcoded;
            // these values are from the big ass func at 0x9899C, around 0x9A9A0 - 0x9AA00;
            // ackchyually, the first 4 bytes are set to 0, but we set them anyway to:
            // 0xAF 0x1B 0xB1 0xFA
            // the magic bytes of an unobfuscated global-metadata.dat file.
            byte[] firstBytes = {0xaf, 0x1b, 0xb1, 0xfa, metadata[4], 0x00, 0x00, 0x00};

            byte[] middleBytes = DecryptInnerMetadataHeader(metadata.Skip(0x8).Take(0x100).ToArray(), key, lastPassHeaderKey);

            // last 8 bytes of metadata header are XOR encrypted.
            byte[] finalBytes = metadata.Skip(0x108).Take(8).Select(b => (byte) (b ^ headerLastBytesKey)).ToArray();

            return firstBytes.Concat(middleBytes).Concat(finalBytes).ToArray();
        }

        /// <summary>
        /// Decrypts metadata body.
        /// <para />
        /// Offset: <c>0x9899C</c> (a very small part of, around <c>0x9A7A8</c>).
        /// </summary>
        /// <param name="metadata">the input metadata</param>
        /// <param name="bodyKeySeed">the metadata body key seed</param>
        /// <returns>the decrypted metadata body</returns>
        public static byte[] DecryptMetadataBody(byte[] metadata, byte bodyKeySeed)
        {
            byte[] body = metadata.Skip(0x110).ToArray();

            // offset: 0xC5C20
            byte key = bodyKeySeed;
            for (int i = 0; i < body.Length; ++i)
            {
                body[i] ^= key;
                key = LoByte((key + 1U << 7) | ((uint) LoByte(key + 1U) >> 1));
            }

            return body;
        }

        /// <summary>
        /// Transforms <c>key 0</c> to obtain <c>key 1</c>.
        /// <para />
        /// Offset: <c>0x1CD24</c>.
        /// </summary>
        /// <param name="key0"><c>key 0</c></param>
        /// <returns><c>key 1</c></returns>
        private static byte[] TransformKey1(byte[] key0)
        {
            return key0.Select(b => (byte) ((~((uint) b) & 0xbd) | (((uint) b) & 0x42))).ToArray();
        }

        /// <summary>
        /// Gets <c>key 1</c> from <c>key 0</c> and checks for custom metadata signature.
        /// <para />
        /// Offset: <c>0x1C540</c>.
        /// </summary>
        /// <param name="metadata">the input metadata</param>
        /// <param name="key0"><c>key 0</c></param>
        /// <returns><c>key 1</c></returns>
        /// <exception cref="InvalidDataException">if actual metadata signature doesn't match expected metadata signature</exception>
        public static byte[] GetKey1(byte[] metadata, byte[] key0)
        {
            // custom metadata signature, bytes 5 to 7 (counting from 0)
            byte[] expectedSignature = {0x4b, 0x9e, 0xec};
            byte[] actualSignature = metadata.Skip(5).Take(3).ToArray();
            if (!expectedSignature.SequenceEqual(actualSignature))
            {
                throw new InvalidDataException($"metadata format not recognized: expected [{string.Join(", ", expectedSignature)}], got: [{string.Join(", ", actualSignature)}]");
            }

            return TransformKey1(key0);
        }

        /// <summary>
        /// Gets <c>key 2</c> from <c>key 1</c>.
        /// <para />
        /// Offset: <c>0xD3484</c>.
        /// </summary>
        /// <param name="key1"><c>key 1</c></param>
        /// <returns><c>key 2</c></returns>
        public static uint[] GetKey2(byte[] key1)
        {
            uint[] key2 = new uint[44];

            for (int i = 0; i < 4; ++i)
            {
                key2[i] = ((uint) key1[i * 4] << 24) | ((uint) key1[i * 4 + 1] << 16) | ((uint) key1[i * 4 + 2] << 8) | key1[i * 4 + 3];
            }

            for (int i = 0; i < 10; ++i)
            {
                int currentDWord = i * 4;
                int nextDWord = currentDWord + 4;

                uint word3 = key2[currentDWord + 3];
                uint word2 = key2[currentDWord + 2];
                uint word0 = key2[currentDWord] ^ ((uint) HiByte(RijndaelTe4[Byte2(word3)]) << 24 | (uint) Byte2(RijndaelTe4[Byte1(word3)]) << 16 | (uint) Byte1(RijndaelTe4[LoByte(word3)]) << 8 | LoByte(RijndaelTe4[HiByte(word3)])) ^ RijndaelRcon[i];
                uint word1 = key2[currentDWord + 1] ^ word0;

                key2[nextDWord] = word0;
                key2[nextDWord + 1] = word1;
                key2[nextDWord + 2] = word2 ^ word1;
                key2[nextDWord + 3] = word3 ^ word2 ^ word1;
            }

            return key2;
        }

        /// <summary>
        /// Gets <c>key 3</c> from <c>key 2</c>.
        /// <para />
        /// Offset: <c>0xD3844</c>.
        /// </summary>
        /// <param name="key2"><c>key 2</c></param>
        /// <returns><c>key 3</c></returns>
        public static uint[] GetKey3(uint[] key2)
        {
            uint[] key3 = key2.ToArray();

            int lastDWord = 40;

            for (int i = 0; i < lastDWord / 2; i += 4)
            {
                for (int j = 0; j < 4; ++j)
                {
                    (key3[i + j], key3[lastDWord - i + j]) = (key3[lastDWord - i + j], key3[i + j]);
                }
            }

            for (int i = 7; i < lastDWord; i += 4)
            {
                for (int j = 0; j < 4; ++j)
                {
                    key3[i - j] = RijndaelTd1[LoByte(RijndaelTe4[Byte2(key3[i - j])])] ^ RijndaelTd0[LoByte(RijndaelTe4[HiByte(key3[i - j])])] ^ RijndaelTd2[LoByte(RijndaelTe4[Byte1(key3[i - j])])] ^ RijndaelTd3[LoByte(RijndaelTe4[LoByte(key3[i - j])])];
                }
            }

            return key3;
        }

        /// <summary>
        /// Gets last pass XOR key for metadata header decryption.
        /// <para />
        /// Offset: <c>0xD3364</c>.
        /// </summary>
        /// <param name="lastPassHeaderKeySeed">last pass XOR key seed for metadata header decryption</param>
        /// <returns>last pass XOR key for metadata header decryption</returns>
        public static byte[] GetLastPassHeaderKey(byte lastPassHeaderKeySeed)
        {
            // while it is 64 bytes, only the first 16 are ever used
            return Enumerable.Range(0, 64).Select(i => (byte) (i + lastPassHeaderKeySeed)).ToArray();
        }
    }
}

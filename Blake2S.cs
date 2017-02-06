/*	BLAKE2.cs source code package - C# implementation

	Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
	Written in 2012 by Christian Winnerlein <codesinchaos@gmail.com>
	Written in 2016 by Uli Riehm <metadings@live.de>

	To the extent possible under law, the author(s) have dedicated all copyright
	and related and neighboring rights to this software to the public domain
	worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with
	this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
using System;
using System.Security.Cryptography;

namespace Crypto
{
	public partial class Blake2S : HashAlgorithm //, IDisposable
	{
		public static uint BytesToUInt32(byte[] buf, int offset)
		{
			return
				((uint)buf[offset + 3] << 3 * 8) |
				((uint)buf[offset + 2] << 2 * 8) |
				((uint)buf[offset + 1] << 1 * 8) |
				((uint)buf[offset]);
		}

		public static void UInt32ToBytes(ulong value, byte[] buf, int offset)
		{
			buf[offset + 3] = (byte)(value >> 3 * 8);
			buf[offset + 2] = (byte)(value >> 2 * 8);
			buf[offset + 1] = (byte)(value >> 1 * 8);
			buf[offset] = (byte)value;
		}

		private readonly int hashSize = 256;

		public override int HashSize { get { return hashSize; } }

		public int HashSizeInBytes { get { return hashSize / 8; } }

		public int HashSizeInUInt32 { get { return HashSizeInBytes / 4; } }

		public Blake2S()
		{
			fanOut = 1;
			maxHeight = 1;
			// leafSize = 0;
			// intermediateHashSize = 0;
		}

		public Blake2S(int hashSizeInBits)
			: this()
		{	
			if (hashSizeInBits < 1 || hashSizeInBits > 256)
				throw new ArgumentOutOfRangeException("hashSizeInBits");
			if (hashSizeInBits % 8 != 0)
				throw new ArgumentOutOfRangeException("hashSizeInBits", "MUST be a multiple of 8");
			
			hashSize = hashSizeInBits;
		}

		// enum blake2b_constant's
		public const int BLAKE2S_BLOCKBYTES = 64;
		public const int BLAKE2S_BLOCKUINT32S = BLAKE2S_BLOCKBYTES / 4;
		public const int BLAKE2S_OUTBYTES = 32;
		public const int BLAKE2S_KEYBYTES = 32;
		public const int BLAKE2S_SALTBYTES = 8;
		public const int BLAKE2S_PERSONALBYTES = 8;

		public const uint IV0 = 0x6A09E667U;
		public const uint IV1 = 0xBB67AE85U;
		public const uint IV2 = 0x3C6EF372U;
		public const uint IV3 = 0xA54FF53AU;
		public const uint IV4 = 0x510E527FU;
		public const uint IV5 = 0x9B05688CU;
		public const uint IV6 = 0x1F83D9ABU;
		public const uint IV7 = 0x5BE0CD19U;

		private bool isInitialized = false;

		private int bufferFilled;
		private byte[] buffer = new byte[BLAKE2S_BLOCKBYTES];
		private uint[] state = new uint[8];
		private uint[] m = new uint[16];
		private uint counter0;
		private uint counter1;
		private uint f0;
		private uint f1;

		public const int ROUNDS = 10;

		public static readonly int[] Sigma = new int[ROUNDS * 16] {
			 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
			14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
			11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
			 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
			 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
			 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
			12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
			13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
			 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
			10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0,
		};

		public virtual uint[] Prepare()
		{
			var c = new uint[8];

			// digest length
			c[0] |= (uint)HashSizeInBytes;

			// Key length
			if (Key != null)
			{
				if (Key.Length > 64)
					throw new ArgumentException("Key", "Key too long");

				c[0] |= ((uint)Key.Length << 8);
			}

			if (IntermediateHashSize > 64)
				throw new ArgumentOutOfRangeException("IntermediateHashSize");

			// bool isSequential = TreeConfig == null;
			// FanOut
			c[0] |= FanOut << 16;
			// Depth
			c[0] |= MaxHeight << 24;
			// Leaf length
			c[0] |= LeafSize << 32;
			// Inner length
			c[2] |= IntermediateHashSize << 8;

			// Salt
			if (Salt != null)
			{
				if (Salt.Length != 8)
					throw new ArgumentException("Salt has invalid length");

				c[4] = BytesToUInt32(Salt, 0);
				c[5] = BytesToUInt32(Salt, 4);
			}
			// Personalization
			if (Personalization != null)
			{
				if (Personalization.Length != 8)
					throw new ArgumentException("Personalization has invalid length");

				c[6] = BytesToUInt32(Personalization, 0);
				c[7] = BytesToUInt32(Personalization, 4);
			}

			return c;
		}

		private uint[] rawConfig;

		public override void Initialize()
		{
			if (rawConfig == null)
			{
				rawConfig = Prepare();
			}
			Initialize(rawConfig);
		}

		/* public static void ConfigBSetNode(ulong[] rawConfig, byte depth, ulong nodeOffset)
		{
			rawConfig[1] = nodeOffset;
			rawConfig[2] = (rawConfig[2] & ~0xFFul) | depth;
		} */

		public virtual void Initialize(uint[] c)
		{
			if (c == null)
				throw new ArgumentNullException("config");
			if (c.Length != 8)
				throw new ArgumentException("config length must be 8 words");

			HashClear();

			state[0] = IV0;
			state[1] = IV1;
			state[2] = IV2;
			state[3] = IV3;
			state[4] = IV4;
			state[5] = IV5;
			state[6] = IV6;
			state[7] = IV7;

			for (int i = 0; i < 8; i++) state[i] ^= c[i];

			isInitialized = true;

			if (Key != null) HashCore(Key, 0, Key.Length);
		}

		// public void Dispose() { Dispose(true); }

		protected override void Dispose(bool disposing) { if (disposing) HashClear(); base.Dispose(disposing); }

		public virtual void HashClear()
		{
			isInitialized = false;

			counter0 = 0U;
			counter1 = 0U;
			f0 = 0U;
			f1 = 0U;

			bufferFilled = 0;
			int i;
			for (i = 0; i < BLAKE2S_BLOCKBYTES; ++i) buffer[i] = 0x00;
			for (i = 0; i < 8; ++i) state[i] = 0U;
			for (i = 0; i < 16; ++i) m[i] = 0U;
		}

		protected bool IsLastNode { get { return f1 == uint.MaxValue; } }

		protected void SetLastNode() { f1 = uint.MaxValue; }

		protected void ClearLastNode() { f1 = 0; }

		protected bool IsLastBlock { get { return f0 == uint.MaxValue; } }

		protected void SetLastBlock()
		{
			if( IsLastNode ) SetLastNode();
			f0 = uint.MaxValue;
		}

		protected void ClearLastBlock()
		{
			if( IsLastNode ) ClearLastNode();
			f0 = 0;
		}

		protected void IncrementCounter( uint inc )
		{
			counter0 += inc;
			if (counter0 == 0) ++counter1;
		}

		protected override void HashCore(byte[] array, int offset, int length)
		{
			Core(array, offset, length);
		}

		public virtual void Core(byte[] array, int offset, int length)
		{
			if (array == null)
				throw new ArgumentNullException("array");
			if (offset < 0)
				throw new ArgumentOutOfRangeException("offset");
			if (length < 0)
				throw new ArgumentOutOfRangeException("length");
			if (offset + length > array.Length)
				throw new ArgumentOutOfRangeException("offset + length");

			if (!isInitialized) Initialize();

			int bytesToFill;
			while (0 < length)
			{
				bytesToFill = Math.Min(length, BLAKE2S_BLOCKBYTES - bufferFilled);
				Buffer.BlockCopy(array, offset, buffer, bufferFilled, bytesToFill);

				bufferFilled += bytesToFill;
				offset += bytesToFill;
				length -= bytesToFill;

				if (bufferFilled == BLAKE2S_BLOCKBYTES)
				{
					IncrementCounter((uint)BLAKE2S_BLOCKBYTES);

					if (BitConverter.IsLittleEndian)
						Buffer.BlockCopy(buffer, 0, m, 0, BLAKE2S_BLOCKBYTES);
					else
						for (int i = 0; i < BLAKE2S_BLOCKUINT32S; ++i)
							m[i] = BytesToUInt32(buffer, (i << 3));

					Compress();

					bufferFilled = 0;
				}
			}
		}

		partial void Compress();

		protected override byte[] HashFinal()
		{
			return Final();
		}

		public virtual byte[] Final()
		{
			var hash = new byte[HashSizeInBytes];
			Final(hash);
			return hash;
		}

		/* public virtual byte[] Final(bool isEndOfLayer)
		{
			var hash = new byte[HashSizeInBytes];
			Final(hash, isEndOfLayer);
			return hash;
		}

		public virtual void Final(byte[] hash)
		{
			Final(hash, false);
		} /**/

		public virtual void Final(byte[] hash) //, bool isEndOfLayer)
		{
			if (hash.Length != HashSizeInBytes)
				throw new ArgumentOutOfRangeException("hash", 
					string.Format("hash.Length must be {0} HashSizeInBytes",
						HashSizeInBytes));

			if (!isInitialized) Initialize();

			// Last compression
			IncrementCounter((uint)bufferFilled);

			SetLastBlock();

			for (int i = bufferFilled; i < BLAKE2S_BLOCKBYTES; ++i) buffer[i] = 0x00;

			if (BitConverter.IsLittleEndian)
				Buffer.BlockCopy(buffer, 0, m, 0, BLAKE2S_BLOCKBYTES);
			else
				for (int i = 0; i < BLAKE2S_BLOCKUINT32S; ++i)
					m[i] = BytesToUInt32(buffer, (i << 3));
			
			Compress();

			// Output
			if (BitConverter.IsLittleEndian)
				Buffer.BlockCopy(state, 0, hash, 0, HashSizeInBytes);
			else
				for (int i = 0; i < HashSizeInUInt32; ++i)
					UInt32ToBytes(state[i], hash, i << 3);

			isInitialized = false;
		}

		public virtual void Compute(byte[] value, byte[] sourceCode)
		{
			Core(sourceCode, 0, sourceCode.Length);
			Final(value);
		}

		public virtual byte[] Compute(byte[] sourceCode)
		{
			Core(sourceCode, 0, sourceCode.Length);
			return Final();
		}

		public override byte[] Hash
		{
			get {
				// if (m_bDisposed) throw new ObjectDisposedException(null);
				// if (State != 0) throw new CryptographicUnexpectedOperationException(Environment.GetResourceString("Cryptography_HashNotYetFinalized"));

				// Output
				var hash = new byte[HashSizeInBytes];
				if (BitConverter.IsLittleEndian)
					Buffer.BlockCopy(state, 0, hash, 0, HashSizeInBytes);
				else
					for (int i = 0; i < HashSizeInUInt32; ++i)
						UInt32ToBytes(state[i], hash, i << 3);
				return hash;
			}
		}


		private uint fanOut;

		public uint FanOut
		{ 
			get { return fanOut; }
			set { 
				fanOut = value; 
				rawConfig = null;
				isInitialized = false;
			}
		}

		private uint maxHeight;

		public uint MaxHeight
		{ 
			get { return maxHeight; }
			set { 
				maxHeight = value; 
				rawConfig = null;
				isInitialized = false;
			}
		}

		private uint leafSize;

		public uint LeafSize
		{ 
			get { return leafSize; }
			set { 
				leafSize = value; 
				rawConfig = null;
				isInitialized = false;
			}
		}

		private uint intermediateHashSize;

		public uint IntermediateHashSize
		{ 
			get { return intermediateHashSize; }
			set { 
				intermediateHashSize = value; 
				rawConfig = null;
				isInitialized = false;
			}
		}


		private byte[] personalization;

		public byte[] Personalization 
		{ 
			get { return personalization; }
			set { 
				personalization = value; 
				rawConfig = null;
				isInitialized = false;
			}
		}

		private byte[] salt;

		public byte[] Salt 
		{ 
			get { return salt; }
			set { 
				salt = value; 
				rawConfig = null;
				isInitialized = false;
			}
		}

		private byte[] key;

		public byte[] Key
		{ 
			get { return key; }
			set { 
				key = value; 
				rawConfig = null;
				isInitialized = false;
			}
		}

	}
}

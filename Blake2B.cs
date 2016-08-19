/*	BLAKE2 reference source code package - C# implementation

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
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Blake2
{
	public partial class Blake2B : HashAlgorithm
	{
		private ulong[] rawConfig;

		private byte[] _Personalization;

		public byte[] Personalization 
		{ 
			get { return _Personalization; }
			set { 
				_Personalization = value; 
				HashClear();
			}
		}

		private byte[] _Salt;

		public byte[] Salt 
		{ 
			get { return _Salt; }
			set { 
				_Salt = value; 
				HashClear();
			}
		}

		private byte[] _Key;

		public byte[] Key
		{ 
			get { return _Key; }
			set { 
				_Key = value; 
				HashClear();
			}
		}

		private uint _IntermediateHashSize;

		public uint IntermediateHashSize
		{ 
			get { return _IntermediateHashSize; }
			set { 
				_IntermediateHashSize = value; 
				HashClear();
			}
		}

		private uint _MaxHeight;

		public uint MaxHeight
		{ 
			get { return _MaxHeight; }
			set { 
				_MaxHeight = value; 
				HashClear();
			}
		}

		private ulong _LeafSize;

		public ulong LeafSize
		{ 
			get { return _LeafSize; }
			set { 
				_LeafSize = value; 
				HashClear();
			}
		}

		private uint _FanOut;

		public uint FanOut
		{ 
			get { return _FanOut; }
			set { 
				_FanOut = value; 
				HashClear();
			}
		}

		private int _hashSizeInBytes;

		public int HashSizeInBytes { get { return _hashSizeInBytes; } }

		public override int HashSize { get { return HashSizeInBytes * 8; } }

		public override byte[] Hash 
		{
			get {
				// if (m_bDisposed) throw new ObjectDisposedException(null);
				// if (State != 0) throw new CryptographicUnexpectedOperationException(Environment.GetResourceString("Cryptography_HashNotYetFinalized"));
				var _hash = new byte[HashSizeInBytes];
				for (int i = 0; i < 8; ++i) UInt64ToBytes(hash[i], _hash, i << 3);
				return _hash;
			}
		}

		public Blake2B() : this(64) { }

		public Blake2B(int hashSizeInBytes)
		{	
			if (hashSizeInBytes <= 0 || hashSizeInBytes > 64)
				throw new ArgumentOutOfRangeException("hashSizeInBytes");
			if (hashSizeInBytes % 8 != 0)
				throw new ArgumentOutOfRangeException("hashSizeInBytes", "must be a multiple of 8");
			
			_hashSizeInBytes = hashSizeInBytes;

			_FanOut = 1;
			_MaxHeight = 1;
			// _LeafSize = 0;
			// _IntermediateHashSize = 0;
		}

		private bool _isInitialized = false;

		private int bufferFilled;
		private byte[] buffer = new byte[256];
		private ulong[] hash = new ulong[8];
		private ulong[] material = new ulong[16];
		private ulong _counter0;
		private ulong _counter1;
		private ulong _finalizationFlag0;
		private ulong _finalizationFlag1;

		public const int NumberOfRounds = 12;
		public const int BlockSizeInBytes = 128;

		public const ulong IV0 = 0x6A09E667F3BCC908UL;
		public const ulong IV1 = 0xBB67AE8584CAA73BUL;
		public const ulong IV2 = 0x3C6EF372FE94F82BUL;
		public const ulong IV3 = 0xA54FF53A5F1D36F1UL;
		public const ulong IV4 = 0x510E527FADE682D1UL;
		public const ulong IV5 = 0x9B05688C2B3E6C1FUL;
		public const ulong IV6 = 0x1F83D9ABFB41BD6BUL;
		public const ulong IV7 = 0x5BE0CD19137E2179UL;

		public static readonly int[] Sigma = new int[NumberOfRounds * 16] {
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
			11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
			7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
			9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
			2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
			12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
			13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
			6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
			10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
		};

		public static ulong BytesToUInt64(byte[] buf, int offset)
		{
			return
				((ulong)buf[offset + 7] << 7 * 8 |
				((ulong)buf[offset + 6] << 6 * 8) |
				((ulong)buf[offset + 5] << 5 * 8) |
				((ulong)buf[offset + 4] << 4 * 8) |
				((ulong)buf[offset + 3] << 3 * 8) |
				((ulong)buf[offset + 2] << 2 * 8) |
				((ulong)buf[offset + 1] << 1 * 8) |
				((ulong)buf[offset]));
		}

		public static void UInt64ToBytes(ulong value, byte[] buf, int offset)
		{
			buf[offset + 7] = (byte)(value >> 7 * 8);
			buf[offset + 6] = (byte)(value >> 6 * 8);
			buf[offset + 5] = (byte)(value >> 5 * 8);
			buf[offset + 4] = (byte)(value >> 4 * 8);
			buf[offset + 3] = (byte)(value >> 3 * 8);
			buf[offset + 2] = (byte)(value >> 2 * 8);
			buf[offset + 1] = (byte)(value >> 1 * 8);
			buf[offset] = (byte)value;
		}

		public virtual ulong[] Prepare()
		{
			var rawConfig = new ulong[8];

			// digest length
			rawConfig[0] |= (ulong)(uint)HashSizeInBytes;

			// Key length
			if (Key != null)
			{
				if (Key.Length > 64)
					throw new ArgumentException("Key", "Key too long");

				rawConfig[0] |= (ulong)((uint)Key.Length << 8);
			}

			if (IntermediateHashSize > 64)
				throw new ArgumentOutOfRangeException("IntermediateHashSize");

			// bool isSequential = TreeConfig == null;
			// FanOut
			rawConfig[0] |= FanOut << 16;
			// Depth
			rawConfig[0] |= MaxHeight << 24;
			// Leaf length
			rawConfig[0] |= LeafSize << 32;
			// Inner length
			rawConfig[2] |= IntermediateHashSize << 8;

			// Salt
			if (Salt != null)
			{
				if (Salt.Length != 16)
					throw new ArgumentException("Salt has invalid length");

				rawConfig[4] = BytesToUInt64(Salt, 0);
				rawConfig[5] = BytesToUInt64(Salt, 8);
			}
			// Personalization
			if (Personalization != null)
			{
				if (Personalization.Length != 16)
					throw new ArgumentException("Personalization has invalid length");

				rawConfig[6] = BytesToUInt64(Personalization, 0);
				rawConfig[7] = BytesToUInt64(Personalization, 8);
			}

			return rawConfig;
		}

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

		public virtual void Initialize(ulong[] config)
		{
			if (config == null)
				throw new ArgumentNullException("config");
			if (config.Length != 8)
				throw new ArgumentException("config length must be 8 words");

			HashClear();

			for (int i = 0; i < 8; i++) hash[i] ^= config[i];

			_isInitialized = true;

			if (Key != null) HashCore(Key, 0, Key.Length);
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing) HashClear();
			base.Dispose(disposing);
		}

		public virtual void HashClear()
		{
			_isInitialized = false;

			hash[0] = IV0;
			hash[1] = IV1;
			hash[2] = IV2;
			hash[3] = IV3;
			hash[4] = IV4;
			hash[5] = IV5;
			hash[6] = IV6;
			hash[7] = IV7;

			_counter0 = 0;
			_counter1 = 0;
			_finalizationFlag0 = 0;
			_finalizationFlag1 = 0;

			bufferFilled = 0;

			Array.Clear(buffer, 0, buffer.Length);

			Array.Clear(material, 0, material.Length);

			if (Personalization != null)
			{
				Array.Clear(Personalization, 0, Personalization.Length);
				Personalization = null;
			}
			if (Salt != null)
			{
				Array.Clear(Salt, 0, Salt.Length);
				Salt = null;
			}
			if (Key != null)
			{
				Array.Clear(Key, 0, Key.Length);
				Key = null;
			}
		}

		partial void Compress(byte[] block, int start);

		public virtual void Core(byte[] array, int start, int count)
		{
			if (array == null)
				throw new ArgumentNullException("array");
			if (start < 0)
				throw new ArgumentOutOfRangeException("start");
			if (count < 0)
				throw new ArgumentOutOfRangeException("count");
			if (start + count > array.Length)
				throw new ArgumentOutOfRangeException("start + count");

			if (!_isInitialized) Initialize();

			int bytesDone = 0, bytesToFill;
			int blocksDone, blockBytesDone;
			do
			{
				bytesToFill = Math.Min(count, buffer.Length - bufferFilled);
				Buffer.BlockCopy(array, start, buffer, bufferFilled, bytesToFill);

				bytesDone += bytesToFill;
				bufferFilled += bytesToFill;
				count -= bytesToFill;
				start += bytesToFill;

				if (bufferFilled >= BlockSizeInBytes)
				{
					for (blocksDone = 0; (blockBytesDone = blocksDone * BlockSizeInBytes) < bufferFilled; ++blocksDone)
					{
						_counter0 += BlockSizeInBytes;
						if (_counter0 == 0) ++_counter1;

						Compress(buffer, blockBytesDone);
					}

					blockBytesDone = --blocksDone * BlockSizeInBytes;
					bufferFilled -= blockBytesDone;

					if (bufferFilled > 0)
					{
						Buffer.BlockCopy(buffer, blockBytesDone, buffer, 0, bufferFilled);
						for (i = bufferFilled; i < buffer.Length; ++i) buffer[i] = 0x00;
					}
				}

			} while (bytesDone < count && start + count < array.Length);
		}

		protected override void HashCore(byte[] array, int start, int count)
		{
			Core(array, start, count);
		}

		protected override byte[] HashFinal ()
		{
			return HashFinal(false);
		}

		protected virtual byte[] HashFinal(bool isEndOfLayer)
		{
			var _hash = new byte[HashSizeInBytes];
			Final(_hash, false);
			return _hash;
		}

		public virtual byte[] Final()
		{
			var _hash = new byte[HashSizeInBytes];
			Final(_hash, false);
			return _hash;
		}

		public virtual void Final(byte[] _hash)
		{
			Final(_hash, false);
		}

		public virtual void Final(byte[] _hash, bool isEndOfLayer)
		{
			if (_hash.Length != HashSizeInBytes)
				throw new ArgumentOutOfRangeException("_hash", "length must be HashSizeInBytes");

			if (!_isInitialized) Initialize();

			// Last compression
			_counter0 += (uint)bufferFilled;
			_finalizationFlag0 = ulong.MaxValue;
			if (isEndOfLayer) _finalizationFlag1 = ulong.MaxValue;

			for (int i = bufferFilled; i < buffer.Length; i++) buffer[i] = 0x00;

			Compress(buffer, 0);

			// Output
			for (int i = 0; i < 8; ++i) UInt64ToBytes(hash[i], _hash, i << 3);

			_isInitialized = false;
		}

		public virtual void Compute(byte[] value, byte[] sourceCode)
		{
			Core(sourceCode, 0, sourceCode.Length);
			Final(value);
		}

		public virtual byte[] Compute(byte[] sourceCode)
		{
			var value = new byte[HashSizeInBytes];
			Core(sourceCode, 0, sourceCode.Length);
			Final(value);
			return value;
		}
	}
}

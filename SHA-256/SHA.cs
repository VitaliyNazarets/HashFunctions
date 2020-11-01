using System;
using System.Linq;
using System.Runtime.CompilerServices;

namespace SHA_256
{
	internal static class KTable
	{
		private readonly static uint[] _data =
		{
			0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
		};

		public static uint Get(int i)
		{
			if (i >= 0 && i < _data.Length)
				return _data[i];
			throw new IndexOutOfRangeException($"Out of range K table - {i} element");
		}
	}

	public class SHA
	{
		private readonly uint[] _hTable =
		{
			0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
		};

		public byte[] GetHash(byte[] message)
		{
			byte[] splitedMessage = new byte[64];
			for (int i = 0; i < message.Length / 64; i++)
			{
				Array.Copy(message, i * 64, splitedMessage, 0, 64);
				uint[] convertedMessage = splitedMessage
					.Select((value, index) => new { value, index })
					.GroupBy((f) => (f.index / 4))
					.Select(f => Converter(f.ElementAt(0).value, f.ElementAt(1).value, f.ElementAt(2).value, f.ElementAt(3).value)).ToArray();
				ToHash(convertedMessage);
			}
			//якщо довжина не кратна 512
			if (message.Length % 64 != 0)
			{
				int len_64 = message.Length / 64 * 64;
				for (int i = len_64; i < message.Length; i++)
				{
					splitedMessage[i % 64] = message[i];
				}
				//Якщо вистачає довжини в кінці речення дописати довжину тексту
				if (message.Length - len_64 < 55)
				{
					splitedMessage[message.Length - len_64] = 0x80;
					for (int i = message.Length - len_64 + 1; i < 55;  i++)
					{
						splitedMessage[i] = 0;
					}
					var lengthInBytes = Converter(Convert.ToUInt32(message.Length * 8));
					splitedMessage[56] = 0;
					splitedMessage[57] = 0;
					splitedMessage[58] = 0;
					splitedMessage[59] = 0;
					splitedMessage[60] = lengthInBytes[0];
					splitedMessage[61] = lengthInBytes[1];
					splitedMessage[62] = lengthInBytes[2];
					splitedMessage[63] = lengthInBytes[3];
					uint[] convertedMessage = splitedMessage
					.Select((value, index) => new { value, index })
					.GroupBy((f) => (f.index / 4))
					.Select(f => Converter(f.ElementAt(0).value, f.ElementAt(1).value, f.ElementAt(2).value, f.ElementAt(3).value)).ToArray();
					ToHash(convertedMessage);

				}
				//якщо не вистачає довжини в кінці масива дописати довжину текста
				else
				{
					splitedMessage[message.Length - len_64] = 0x80;
					for (int i = message.Length - len_64 + 1; i < splitedMessage.Length; i++)
					{
						splitedMessage[i] = 0; 
					}
					uint[] convertedMessage = splitedMessage
					.Select((value, index) => new { value, index })
					.GroupBy((f) => (f.index / 4))
					.Select(f => Converter(f.ElementAt(0).value, f.ElementAt(1).value, f.ElementAt(2).value, f.ElementAt(3).value)).ToArray();
					ToHash(convertedMessage);

					for (int i = message.Length - len_64 + 1; i < 55; i++)
					{
						splitedMessage[i] = 0;
					}
					var lengthInBytes = Converter(Convert.ToUInt32(message.Length));
					splitedMessage[56] = 0;
					splitedMessage[57] = 0;
					splitedMessage[58] = 0;
					splitedMessage[59] = 0;
					splitedMessage[60] = lengthInBytes[0];
					splitedMessage[61] = lengthInBytes[1];
					splitedMessage[62] = lengthInBytes[2];
					splitedMessage[63] = lengthInBytes[3];
					convertedMessage = splitedMessage
					.Select((value, index) => new { value, index })
					.GroupBy((f) => (f.index / 4))
					.Select(f => Converter(f.ElementAt(0).value, f.ElementAt(1).value, f.ElementAt(2).value, f.ElementAt(3).value)).ToArray();
					ToHash(convertedMessage);
				}

			}
			return ((uint[])_hTable.Clone()).Select(f => Converter(f)).SelectMany(f => f).ToArray();
		}
		private uint Shift(uint value, int step)
		{
			return value >> step | value << (32 - step);
		}

		private void ToHash(uint[] message)
		{
			uint[] table = new uint[64];
			for (int i = 0; i < message.Length; i++)
				table[i] = message[i];
			for (int i = message.Length; i < table.Length; i++)
			{
				var t11 = Shift(table[i - 15], 7);
				var t12 = Shift(table[i - 15], 18);
				var t13 = (table[i - 15] >> 3);
				var s0 = Shift(table[i - 15], 7) ^ Shift(table[i - 15], 18) ^ (table[i - 15] >> 3);
				var s1 = Shift(table[i - 2], 17) ^ Shift(table[i - 2], 19) ^ (table[i - 2] >> 10);
				table[i] = Convert.ToUInt32((long) ((long)table[i - 16] + (long)s0 + (long)table[i - 7] + (long)s1) % (long)Math.Pow(2, 32));
			}
			uint[] t = new uint[8];
			for (int i = 0; i < t.Length; i++)
				t[i] = _hTable[i];

			for (int i = 0; i < 64; i++)
			{
				uint t1 = 0, t2 = 0;
				var Σ0 = Shift(t[0], 2) ^ Shift(t[0], 13) ^ Shift(t[0], 22);
				var Ma = (t[0] & t[1]) ^ (t[0] & t[2]) ^ (t[1] & t[2]);
				t2 = Σ0 + Ma;
				var Σ1 = Shift(t[4], 6) ^ Shift(t[4], 11) ^ Shift(t[4], 25);
				var Ch = (t[4] & t[5]) ^ ((~t[4]) & t[6]);
				t1 = t[7] + Σ1 + Ch + KTable.Get(i) + table[i];
				t[7] = t[6];
				t[6] = t[5];
				t[5] = t[4];
				t[4] = t[3] + t1;
				t[3] = t[2];
				t[2] = t[1];
				t[1] = t[0];
				t[0] = t1 + t2;
			}

			for (int i = 0; i < _hTable.Length; i++)
				_hTable[i] = _hTable[i] + t[i];
		}

		private static uint Converter(byte x0, byte x1, byte x2, byte x3)
		{
			return (uint)(x3 + x2 * Math.Pow(2, 8) + x1 * Math.Pow(2, 16) + x0 * Math.Pow(2, 24));
		}

		private static byte[] Converter(uint value)
		{
			var v1 = (byte)(value / Math.Pow(2, 24));
			var v2 = (byte)((value - v1 * Math.Pow(2, 24)) / Math.Pow(2, 16));
			var v3 = (byte)((value - v1 * Math.Pow(2, 24) - v2 * Math.Pow(2, 16)) / Math.Pow(2, 8));
			var v4 = (byte)((value - v1 * Math.Pow(2, 24) - v2 * Math.Pow(2, 16) - v3 * Math.Pow(2, 8)));
			return new byte[] { v1, v2, v3, v4 };
		}
	}
}

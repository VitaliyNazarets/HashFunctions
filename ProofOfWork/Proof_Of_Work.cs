﻿using SHA_256;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ProofOfWork
{
	public enum HashType
	{
		SHA
	}
	public class Proof_Of_Work
	{
		private readonly int _k;
		private readonly HashType hash;
		public Proof_Of_Work(int k, HashType hashType)
		{
			hash = hashType;
			_k = k;
		}
		private byte[] array = new byte[1];
		bool IsCollision(ref byte[] result)
		{
			bool isCollision = true;
			int i = 0;
			int j = 0;
			while (i + j < _k && isCollision)
			{
				if (result[i] > Math.Pow(2, 7 - j))
					isCollision = false;
				j++;
				if (j > 7)
				{
					i++;
					j = 0;
				}
			}
			if (isCollision)
				return isCollision;
			return isCollision;
		}
		public void BrootForce()
		{
			int len = 0;
			int paralelTasks = 16;
			bool isColision = false;
			while (!isColision)
			{
				List<Task> tasks = new List<Task>();
				for (int i = 0; i < paralelTasks; i++)
				{
					var task = Task.Run(() =>
					{
						SHA sha = new SHA();
						var k = Enumerable.Repeat((byte)'x', i).ToArray();
						var t = sha.GetHash(k);
					});
				}
				Task.WhenAll(tasks);
				len += paralelTasks;
			}
		}
	}
}
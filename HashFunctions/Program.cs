using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using ProofOfWork;
using SHA_256;

namespace HashFunctions
{
	class Program
	{
		static void Main(string[] args)
		{
			Proof_Of_Work pow = new Proof_Of_Work(9, HashType.SHA);
			var time = Stopwatch.StartNew();
			pow.BrootForce();
			time.Stop();
			Console.WriteLine($"{time.Elapsed.Minutes} : {time.Elapsed.Seconds}.{time.Elapsed.Milliseconds}");
			Console.ReadKey();
			//SHA sha = new SHA();
			//for (int i = 0; i < 256; i++)
			//byte[] array = ("Is it real? Niceeee").Select(f => (byte)f).ToArray();
			//var result = sha.GetHash(array);
			//Console.WriteLine(string.Join(" ", result.Select(f => $"{f:x2}")));
			//Console.ReadKey();
		}
	}
}

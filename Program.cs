using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Globalization;

namespace Crypto
{
	internal static class Program
	{
		static void Main(string[] args) 
		{
			int argsI; string command;
			Dictionary<string, string> dictionary = ReadConsoleArguments(args, out argsI, out command);

			if (string.IsNullOrEmpty(command) || command.Equals("Blake2B", StringComparison.OrdinalIgnoreCase))
			{
				Blake2B(dictionary);
				return;
			}
			if (command.Equals("Blake2S", StringComparison.OrdinalIgnoreCase))
			{
				Blake2S(dictionary);
				return;
			}

			string format =
					"  HELP: ./Blake2B.exe --In=./Hallo.txt -- Blake2B{0}"
				+	"        ./Blake2B.exe [ --option=value ] [ -- ] [ command ]{0}"
				+	"{0}"
				+	"    Option: --In=./FileName.txt is required{0}"
				+	"{0}"
				+	"  Commands: Blake2B (Default), Blake2S";
			
			Console.WriteLine(format, Environment.NewLine);
		}

		public static void Blake2B(IDictionary<string, string> dictionary)
		{
			FileInfo inFile = null;
			if (dictionary.ContainsKey("In"))
			if (File.Exists(dictionary["In"]))
				inFile = new FileInfo(dictionary["In"]);
			if (inFile == null || !inFile.Exists) {
				Console.WriteLine("Blake2B: --In file not found");
				return;
			}

			// using (var hash = new Blake2B()) value = hash.ComputeHash(bytes);

			byte[] hashValue;
			using (var fileIn = new FileStream(inFile.FullName, FileMode.Open))
			using (var hash = new Blake2B())
			{
				var buffer = new byte[512];
				int bufferL, fileI = 0;
				long fileL = inFile.Length;
				do
				{
					bufferL = fileIn.Read(buffer, 0, buffer.Length);
				
					if (bufferL > 0)
					{
						hash.Core(buffer, 0, bufferL);
					}

					fileL -= bufferL;
					fileI += bufferL;
				
				} while(0 < fileL);

				hashValue = hash.Final();
			}

			foreach (byte v in hashValue) Console.Write("{0:x2}", v);
			Console.WriteLine();
		}

		public static void Blake2S(IDictionary<string, string> dictionary)
		{
			FileInfo inFile = null;
			if (dictionary.ContainsKey("In"))
			if (File.Exists(dictionary["In"]))
				inFile = new FileInfo(dictionary["In"]);
			if (inFile == null || !inFile.Exists) {
				Console.WriteLine("Blake2S: --In file not found");
				return;
			}

			// using (var hash = new Blake2S()) value = hash.ComputeHash(bytes);

			byte[] hashValue;
			using (var fileIn = new FileStream(inFile.FullName, FileMode.Open))
			using (var hash = new Blake2S())
			{
				var buffer = new byte[256];
				int bufferL, fileI = 0;
				long fileL = inFile.Length;
				do
				{
					bufferL = fileIn.Read(buffer, 0, buffer.Length);

					if (bufferL > 0)
					{
						hash.Core(buffer, 0, bufferL);
					}

					fileL -= bufferL;
					fileI += bufferL;

				} while(0 < fileL);

				hashValue = hash.Final();
			}

			foreach (byte v in hashValue) Console.Write("{0:x2}", v);
			Console.WriteLine();
		}



		static Dictionary<string, string> ReadConsoleArguments(string[] args, out int argsI, out string command)
		{
			argsI = 0;

			int nameI, dashs;
			string arg, argName;
			var dictionary = new Dictionary<string, string>(StringComparer.CurrentCultureIgnoreCase);
			do
			{
				if (args.Length == 0) break;

				arg = args[argsI];
				nameI = arg.IndexOf('=');
				dashs = arg.StartsWith("--") ? 2 : (arg.StartsWith("-") ? 1 : 0);
				if (dashs > 0)
				{
					if (arg.Length == dashs)
					{
						break;
					}
					if (nameI > -1)
					{
						argName = arg.Substring(dashs, nameI - dashs);
						arg = arg.Substring(nameI + 1);
						dictionary.Add(argName, arg);
						continue;
					}
					argName = arg.Substring(dashs);
					dictionary.Add(argName, string.Empty);
					continue;
				}

				--argsI;
				break;
			} while (++argsI < args.Length);

			command = string.Empty;
			if (argsI + 1 < args.Length)
			{
				command = args[++argsI];
			} /**/

			return dictionary;
		}
	}
}



**﻿﻿Blake2B.cs source code package - C# implementation**

```
Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
Written in 2012 by Christian Winnerlein <codesinchaos@gmail.com>
Written in 2016 by Uli Riehm <metadings@live.de>

To the extent possible under law, the author(s) have dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with
this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
```

**Usage 1**

Have "one" Blake2B hash value.

```
using Blake2;
using System;
using System.Text;


	string text = "HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT";
	byte[] bytes = Encoding.UTF8.GetBytes(text);
	byte[] value;

	using (var hash = new Blake2B()) value = hash.ComputeHash(bytes);

```

**Usage 2**

Have "many" Blake2B hash values.

```
using Blake2;
using System;
using System.Text;


	byte[] textBytes = Encoding.UTF8.GetBytes("HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT");

	byte[] hashSource = new byte[sizeof(UInt64) + textBytes.Length];
	Buffer.BlockCopy(textBytes, 0, hashSource, sizeof(UInt64), textBytes.Length);

	var hashValue = new byte[64];

	UInt64 i = 0; // threadI;

	using (var hash = new Blake2B())
	{
		do
		{
			Blake2B.UInt64ToBytes(i, hashSource, 0);

			hash.Compute(hashValue, hashSource);

			// if (Quersumme(i + 1) == 1) Console.WriteLine ...

		} while (UInt64.MaxValue > (i += 1)); // threadC));
	}

```

**Example 1**

```
~/Blake2B.cs/bin/Debug $ echo -n HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT > ./Hallo.txt

~/Blake2B.cs/bin/Debug $ hexdump ./Hallo.txt 
0000000 4848 4848 4141 4141 4c4c 4c4c 4f4f 4f4f
0000010 5757 5757 4545 4545 4c4c 4c4c 5454 5454
0000020

~/Blake2B.cs/bin/Debug $ mono ./Blake2B.exe --In=./Hallo.txt
bbc9e82dbf9a8897a5ec2f6836c381dbe27ac0b8ecd9912afa67459ef9474d70a52bf24ad5dcf29dbb8004d19a387b6516cc47ffae99d59d52efc013456c6b48
```

Ask questions on [stackoverflow](http://stackoverflow.com/questions/tagged/c%23+blake2) using tags `C#``Blake2` !


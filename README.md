Pufferfish2
==========

_Pufferfish2_ is an adaptive, cache-hard password hashing scheme that attempts to improve upon [bcrypt](https://en.wikipedia.org/wiki/Bcrypt). Pufferfish2 uses a modified version of the Blowfish key setup, and improves some of the drawbacks of bcrypt's original Eksblowfish algorithm. 

Pufferfish2 is based on the [Password Hashing Competition](https://password-hashing.net) candidate Pufferfish, which was selected as a finalist, but was not selected as the winner. While Pufferfish V0 wasn't terrible, V1 was hastily developed and the reference code was plagued with several (very nasty) bugs. Both V0 and V1 also had some minor design flaws, although these did not affect the operation of the algorithm under normal conditions.

Pufferfish2 includes several bug fixes and general improvements over Pufferfish, as well as incorporates some of the feedback received on Pufferfish during the PHC review and selection process.

### Features

* Supports passwords of any length (vs. bcrypt's max of 72 characters), any encoding, any character (0x00 - 0xff).
* Dynamic s-boxes scale to fill L2 or L3 cache (and well beyond), forcing GPU attacker to use global memory.
* Inherits bcrypt's cache hardness (small-but-frequent pseudo-random reads) but performs many more than bcrypt for the same target runtimes, and also adds larger, less-frequent memory reads and writes.
* Supports up to 2<sup>63</sup> iterations.
* Upgrades Blowfish to 64-bit integers, resulting in improved performance vs. bcrypt for 64-bit defenders, and decreased performance for 32-bit attackers(e.g., GPUs.)


### Pufferfish2 vs. bcrypt - By the Numbers

Perhaps the best way to illustrate Pufferfish2's improvements over bcrypt is to simply break down the numbers. Using an Intel Xeon E-2176G CPU (6 cores / 12 threads, 256KiB per-core L2 cache, 3.7 GHz base / 4.7 GHz turbo), the following cost values both provide nearly identical ~900ms runtimes:

```
Pufferfish2  : cost_t = 9, cost_m = 8
bcrypt       : cost = 15
```

Using these parameters...

##### Pufferfish2
* Uses 256 KiB of memory (resident in L2 cache)
* Pre-hashes the supplied password and salt
* Performs 539,264,128 random 64-bit reads
* Reads, hashes, and writes 135,004,160 bytes of data

#### bcrypt
* Uses 4 KiB of memory (resident in L1 cache)
* Performs 6,538,944 random 32-bit reads

In other words, in nearly the same duration of time, Pufferfish2 performs 82.5x more random reads than bcrypt (64-bit vs 32-bit as well), plus performs pre-hashing and sequential read-hash-write operations on 128.75 MiB of data. 

From this example, it is overwhelmingly obvious to see that Pufferfish2 is much stronger than bcrypt, while providing much better GPU resistance than bcrypt.


### Acknowledgements

Pufferfish2 builds upon prior works by Bruce Schneier (Blowfish) and Niels Provos & David Mazieres (bcrypt). However, Pufferfish is not endorsed by these individuals. Its creation was prompted by the Password Hashing Competition, and its design was inspired by work to accelerate bcrypt cracking by Steve Thomas, Jens Steube, Alexander Peslyak, Sayantan Datta, and Katja Malvoni. Special thanks is due to Steve Thomas and Alexander Peslyak for their review and analysis of Pufferfish, and to Steve Thomas again for his input on Pufferfish2.


### Usage

* Create a new password hash

```
#include "pufferfish.h"
...
int ret = 0;
char hash[PF_HASHSPACE];

if ((ret = pf_newhash(password, password_length, time_cost, memory_cost, hash)) != 0) {
    fprintf(stderr, "Error: %s\n", strerror (ret));
    return ret;
}
```

* Validate a password against an existing hash

```
#include "pufferfish.h"
...
int ret = 0;

if ((ret = pf_checkpass(correct_hash, password, password_length)) != 0) {
    fprintf(stderr, "Invalid password!\n");
    return ret;
}
```

### Choosing Parameters

The `time_cost` parameter is the log2 iteration count, or the number of times the function loops over itself. For example, a `time_cost` value of "5" would be 2^5 (32) iterations.

The `memory_cost` parameter is the total log2 size of the s-boxes in kibibytes (thousands of binary bytes.) For example, a `memory_cost` value of "8" would be 2^8 kibibytes (256 KiB.)

The `memory_cost` parameter *must always* be selected first. TL;DR, just set `memory_cost` value equal to the per-core L2 cache size of your specific CPU:

```
+---------------------------------+
| Per-core L2 cache | memory_cost |
|-------------------|-------------|
| 256 KiB           | 8           |
| 512 KiB           | 9           |
| 1 MiB             | 10          |
| 2 MiB             | 11          |
+---------------------------------+
```

Pufferfish2 is a _cache-hard_ algorithm, and thus _needs_ to run in on-chip cache (preferably L2 cache, but L3 cache may be used where long runtimes are desirable.) For optimal GPU resistance, this parameter should *never* be set lower than "7" (128 KiB), as GPUs currently have up to 96 KiB of shared memory per SM. For optimal CPU performance, this parameter should match the per-core L2 cache size of your specific CPU. In Linux, this information may be found at `/sys/devices/system/cpu/cpu0/cache/index2/size`. For example, an Intel Xeon E5-2620 v4 has 256 KiB of per-core L2 cache; therefore, the optimal `memory_cost` value for this CPU is "8" (2^8, or 256 KiB.) Conversely, an Intel Xeon Silver 4110 has 1 MiB of per-core L2 cache; therefore, the optimal `memory_cost` parameter for this CPU is "10" (2^10, or 1 MiB.)

You _may_ push out into L3 cache if you would like. However, you are *strongly encouraged* to keep Pufferfish2 in L2 cache unless you are specifically targeting runtimes > 1000 ms. That said, you are *strongly discouraged* from pushing out beyond L3 cache. While Pufferfish2 does _technically_ support `memory_cost` values up to 63 (8 EiB), it is a cache-hard algorithm, not a memory-hard algorithm, and thus it is strongly recommended that you stay in on-chip cache and do not push out to off-chip memory.

Once the optimal `memory_cost` value has been selected, you will need to determine the optimal `time_cost` value. To do this, you will need to know the maximum number of authentication attempts per second your application needs to support. Once you know this number, you will need to benchmark your actual application at various `time_cost` settings until you find the highest value that enables you to still meet your target number of authentication attempts per second.

If your application is rather low-volume and you do not expect to support many simultaneous authentication attempts, then you should target a runtime duration instead. For applications where Pufferfish2 is being employed during interactive authentication (such as a web application), you will likely need to strike a balance between strong security and good UX, and thus you will likely want to select a target runtime of 1000ms or less. If you are developing an application that does not require interactive authentication, or where authentication happens very infrequently and runtimes greater than 1000ms are acceptable, then you may pick any target that seems appropriate. Then, benchmark your actual appliaction at various `time_cost` settings until you find the highest value that enables you to meet your target runtime.

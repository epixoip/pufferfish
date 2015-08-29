Pufferfish V2
==========

_Pufferfish V2_ is an adaptive password hashing scheme that attempts to improve upon the Blowfish block cipher and bcrypt's _Eksblowfish_ algorithm. 

V0 and V1 of Pufferfish were submitted to the [Password Hashing Competition](https://password-hashing.net) and the candidate was selected as a finalist, but was not selected as the winner. However, V1 of Pufferfish was hastily developed, and the reference design was plagued with several (very nasty) bugs. Both V0 and V1 also had some minor design flaws, although these did not affect the operation of the algorithm under normal conditions. 

V2 includes several bug fixes and improvements over V1, as well as incorporates some of the feedback received during the PHC review and selection process.

###Features

* Supports passwords of any length (vs. bcrypt's max of 72 characters), any encoding, any character (0x00 - 0xff)
* Dynamic s-boxes scale from 1 KiB to 8 EiB, scalable to large cache sizes forcing use of global memory for GPU attackers (e.g. 1 MiB vs bcrypt's 4 KiB)
* Supports up to 2<sup>63</sup> iterations
* Upgrades Blowfish to 64-bit integers, resulting in improved performance vs. bcrypt for 64-bit defenders, and decreased performance for 32-bit attackers, e.g. GPUs
* Inherits bcrypt's GPU resistance (small-but-frequent pseudorandom memory accesses), but also adds larger, less-frequent memory reads.


###Acknowledgements

Pufferfish builds upon prior works by Bruce Schneier (Blowfish) and Niels Provos & David Mazieres (bcrypt). However, Pufferfish is not endorsed by these individuals. Its creation was prompted by the Password Hashing Competition, and its design was inspired by work to accelerate bcrypt cracking by Steve Thomas, Jens Steube, Alexander Peslyak, Sayantan Datta, and Katja Malvoni. Special thanks is due to Steve Thomas and Alexander Peslyak for their review and analysis of V0 and V1.


###Usage

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

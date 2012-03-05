===============================
WARNING WARNING WARNING WARNING
===============================

This is untested, pre-alpha code which may not even run. I've got every intention on finishing it though.

For more information, check out the Stanford Javascript Crypto Library here:

  http://bitwiseshiftleft.github.com/sjcl/

====================================================
About the Java SJCL Compatibility Library (Java SCL)
====================================================

Author: Maarten Bodewes
License: MIT licensed

The Java side implements the following:

PBKDF2 using SHA-256
AES/CCM for all parameters (key and tag sizes)
Generation and parsing of the parameters in SJCL's JSON format  

It has the following limitations:

No support for OCB-2
[No support for cipher text only communications?]
[No support for encryption with just a key?]

It depends on the following libraries:

[The free Java implementation of Password Based Key Derivation Function 2 (as
 defined by RFC 2898). Copyright (c) 2007 Matthias Gärtner. LGPL licensed.]
 
 - The Bouncy Castle libraries - MIT-like license.
 
 - Jackson, a Java JSON parser - Apache License

The library is provided as is and does not provide an extensive test framework.  

===================================================
About the Stanford Javascript Crypto Library (SJCL)
===================================================

The library can be found at http://bitwiseshiftleft.github.com/sjcl/

About the library
=================

The library has been set up as a research vehicle by a university and should be regarded as such. The pages have
seemingly gone into the public domain and are maintained by the original authors, who seems to be employed elsewhere
by now.

About the security of encryption in JavaScript
==============================================

First of all, JavaScripts main usage is in web-browsers. Web browsers don't provide a secure environment for the
execution of encryption algorithms. It should not be forgotten that there is no protection against man-in-the-middle
attacks if SSL/TLS is not deployed (HTTPS) - not even for the code itself. JavaScript encryption primitives cannot
replace SSL/TLS in any way. JavaScript in browsers does not have access to a source of randomness; it has to
implement a secure random generator out of information that becomes available when browsing a web page. It's main
use would be application level protection for scripts that have been deployed over HTTPS. As HTTPS already provides
transport level security, it's use is relatively limited.

The SJCL algorithms
===================

SJCL uses safe and standardized algorithms, which is a good thing. The configuration of PBKDF2 (defined in the PKCS#5
standard) is normally not configured with SHA-256, which makes it hard to create the protocols in other platforms.
The CCM cipher is not much used at all and it is likely that GCM will surpass it. This makes creating a compatible
implementation in another platform tricky. OCB2 mode is also available, but it is likely that platforms won't support
it because of IP issues (there exist multiple US patents that might be applicable to the algorithm). OCB2 functionality
has not been implemented or tested by the author of this library. The patent situation of OCB2 has been described in a
short sentence on the demo page.

The NONCE, or "IV"
------------------

The algorithms seem to comply to all NIST test vectors, but there is a small catch regarding the use of the CCM
algorithm: the SJCL library mentions the use of a random IV for the algorithm. The algorithm does however *not* use an
IV. Instead it requires a NONCE of a certain size, as explained in Appendix A of the NIST CCM specification. The
library basically creates an IV of 16 octets, which is the block size required by CCM. The NONCE however has a size
of 7 to 13 octets (inclusive), which is dependent on the size of the plain text. The SJCL library library only uses
the leftmost octets of the "IV" being transmitted. This fact is not explained anywhere, and the JSON format
used by the convenience library simply stores all 16 octets of the "IV".

The methods deployed in the convenience.js component
====================================================

Although the core algorithms have been described, this is not the case for the convenience.js component, which
seems to be written as an afterthought. This assumption is made more likely since the implementation seems to be mainly
a vehicle for an academical paper.

The following observations can be made:

UTF-8 encoding
--------------

The convenience library always uses UTF-8 character encoding where character encoding is required. At least, it does now
for the associated data.

Base64 without padding
----------------------

The JSON format does not use define encoding of binary strings, so instead base 64 encoding is used within a text
string. This base 64 encoding does not use any padding characters. Some base 64 decoders may misinterpret these
strings and either return an error or a octet string of too many bytes. This encoding is also used if the parameters
are not send with the cipher text in the demo page of SJCL.

URL encoding
------------

The associated data (adata) is first character encoded and send to the cipher. It is represented as an URL encoded
text string within the JSON format.

The JSON elements
-----------------

"v": the version number, 1 for this protocol
"salt": the salt as a base 64 encoded string (see above)
"iter": the number of iterations of the PBKDF2 function
"cipher": the algorithm, "aes"
"ks": the key size in bits
"mode": the cipher mode, "ccm" or "ocb2"
"iv": the IV as a base 64 string (see above)
"ts": the tag size, used for integrity control and authentication with CCM
"adata": an URL encoded string of the authentication data (see above)
"ct": the cipher text as a base 64 encoded string

The inconvenient error in the SJCL libraries
============================================

The library is only compatible with the JSCL 0.8 and higher, because the author of *this* library found out that
the associated data in the convenience.js file (the "adata" parameter) used on the web page was not encoded. Subsequent
digging by the authors of the SJCL library showed that the "adata" parameter was not taken into account at all. This
explained why the Java test code failed for each and every "adata" parameter different from the empty string. Although
the core AES/CCM implementation has been tested against the NIST vectors, it seems that the surrounding convenience.js
didn't go through any qualification. 

A security advisory and subsequent fix were quickly published, and this library will only be compatible with the version
after the fix, although it is likely that encrypted text without associated data *will* be compatible with the Java
side library.

Security advisory:

http://groups.google.com/group/sjcl-discuss/browse_thread/thread/be07b029f0a63077



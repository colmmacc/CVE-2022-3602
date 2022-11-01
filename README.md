# CVE−2022-3602

### What is this?

This document and repository is a write-up of CVE−2022-3602, a punycode buffer
overflow issue in OpenSSL. It's an "anti-POC" (the issue does not appear to
exploitable) intended for folks who maintain their own OpenSSL builds and for
compiler maintainers.

There is a seperate CVE in the same release, CVE-2022-3786, which also leads to
buffer overflows but an attacker can't control the content in that case. There
is no reproduction for that issue here, but that issue can lead to a Denial of
Service due to crash.

Crashes and Buffer overﬂlows are never good and if you are using OpenSSL 3.0.x,
it is prudent to update as soon as possible.

Feel free to report any errors or omissions via GitHub issues or pull-requests.

### What is the issue?

There is an off-by-one issue in how `ossl_punycode_decode` handles punycode
decoding that results in a 4-byte overflow. This issue is reasonable only when
OpenSSL processes a certificate chain and requires two conditions. Firstly, a
CA or Intermediary certificates in a chain must contain a name-constraint field
that uses punycode.

    nameConstraints = permitted;email:xn-maccrthaigh-n7a.com

Secondly, the leaf certificate must contain a SubjectAlternateName (SAN)
otherName field that specifies a SmtpUTF8Mailbox string.

    otherName = 1.3.6.1.5.5.7.8.9;UTF8:admin@xn-maccrthaigh-n7a.com

when triggered, the punycode in the nameConstraints field, but not the punycode
in the otherName field, will be handled by the vulnerable OpenSSL punycode
parsing.

## How easy is it to trigger this issue?

David Benjamin and Matt Caswell determined that nameConstraint checking occurs
after ordinary certificate chain validation and signature verification. For
most applications this means that the issue can not be triggered with a
self-signed certificate or invalid chain.

Note that openssl's `s_client` and `s_server` applications are intended
for debugging and do not stop processing when a chain is invalid.

A trusted CA or Intermediate will have to contain the malicious payload, and
will also have to have signed the leaf certificate that triggers the issue.

There may be some environments where untrusted parties are the CAs or
Intermediaries, for example a hosting service that supports customer-provided
Private CAs, but this is not common.

## Does the issue lead to Remote Code Execution?

The answer for many applications will be "no" because of how the compiler has
laid out the stack and because of the presence of other protections such as
stack canaries / stack cookies, padding, PIE, FORTIFY\_SOURCE.

The the issue does lead to an overflow of 32-bits on the stack. This is not
enough to directly execute shell code, but it may enough to alter the control
flow of an application. For example jumping to shell-code that has been
embedded in an X509 certificate chain may be possible if this data is also
copied onto the stack in an executable location.

On every Linux platform I've tested, the overflow occurs into padding and is
harmless. In theory, a compiler may lay out variables such that the overflow
occurs into one of the other variables in the `ossl_a2ulabel` function.

Depending on inlining the full-list of variables present is:

    outptr, inptr, size, result, tmpptr, delta, seed, utfsize

and none appear to me to provide an obvious path to privilege escalation or
interesting control.

I've attached a tarball with tools that can be used to create reproductions and
overflows with as much control over all four bytes as is possible. The
reference reproduction string ( `xn--ww90271...aaaa`) overflows the four bytes
with the values `0xFF 0x0F 0x0F 0x0F`. If that does not crash an application,
it is possible (likely?) that that application is not vulnerable.

## How can I reproduce this issue?

The shell script `run-poc` can be used to generate a malicious certificate chain.
A malicous CA certificate is generated from `ca.cnf` and a triggering leaf
certificate is generated from `leaf.cnf`.

The CA certificate uses the following reference payload:

`xn--ww902716aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

A python script can be used to generate other punycode strings for different
payloads.

When executed `run-poc` will run an openssl client and server and attempt to
exploit the issue ten times.

A vulnerable OpenSSL will likely crash. That doesn't mean that the version of
OpenSSL is vulnerable to an RCE, as stack canaries and stack cookie protections
also typically cause a (safer) application crash. Also note that this in no
changes the severity of the other CVE in the same release.

## How does this issue work?

It is surprisingly nuanced to gain near-full control of all four overflow bytes
and requires exploiting OpenSSL's punycode decoder with non-standard / invalid
punycode. The tarball attached contains a script which can construct a
string that handles the nuance. What follows is an explanation of how it works.

### Setting the stage

The security issue is in `ossl_punycode_decode()`

    int ossl_punycode_decode(const char *pEncoded, const size_t enc_len,
                             unsigned int *pDecoded, unsigned int *pout_length)

`ossl_punycode_decode` is invoked from `ossl_a2ulabel`.  The `pEncoded` buffer
is a more or less arbitrarily-sized buffer that comes from an X509 certificate
chain. It's the part that comes after any "xn--" in a nameConstraint field. See
the [reproduction] for how to reproduce such a certificate chain.

`pDecoded` is a `LABEL_BUF_SIZE` sized array of `unsigned int`s.
`LABEL_BUF_SIZE` is 512, and on most platforms an `unsigned int` is going to be
4 bytes wide.  So on most platforms `pDecoded` is 2048 bytes in length.

### The scene

Inside `ossl_punycode_decode()` the crux of the issue is this incorrect length check:

     if (written_out > max_out)

`max_out` corresponds to `*pout_length` which is always 512. And `written_out`
keeps track of how many `unsigned int`s have been written to `pDecoded`.
Because `written_out` is incremented later only after writing, this faulty
check allows 513 `unsigned int`s to be written to `pDecoded`.  The end result
looks something like this ...

    pDecoded = [ ... , 'X , 'Y' , 'Z' ] 'P'
    // Indices         509   510   511

Here, per C's convention, indices are zero-indexed, so slot number 511 is the
512th element in the array. `'P'` is a four-byte payload that has been put out
of bounds, beyond the space allocated on the stack for the `buf` buffer in
`ossl_a2ulabel()` which is what `pDecoded` points to.

Four bytes is a small overflow, and is not enough to carry a nop-sled or
directly execute shell code but is enough to alter the control flow of an
application. For example jumping to shell-code that has been embedded in an
x509 certificate chain may be possible, depending on how this data (or copied
fragments of this data) is stored and whether that memory is executable.
However there is still more difficulty for a would-be attacker.

Firstly, the compiler's padding and alignment of the stack, or defenses such as
stack canaries, may make any exploitation completely impossible.

Secondly, there is only one path to `ossl_punycode_decode()` and this path uses
a buffer on the stack. This makes it unlikely that the issue can be used for
concurrent 4 byte overflows in different memory locations.

### Punycode decoding

Punycode strings basically have two forms. One is `xn--c1yn36f` (點看) and
another is `xn--maccrthaigh-n7a` (maccárthaigh).  The part that comes after the
last `-` delimiter is a 36-ary bootstring encoding of any unicode code-points
that aren't basic ordinary ascii along with the string position to insert them.
What's important for now is that the decoding process in
`ossl_punycode_decode()` produces two values. One is 'n' which is the `unsigned
int` code-point value to be inserted, and the other is 'i' which is the
position in the buffer to insert it.

The writing can happen in two different ways. If `i` is somewhere in the middle
of the string then there's  a `memmove()` which first "makes space" by copying
everything to the right one slot:

    memmove(pDecoded + i + 1, pDecoded + i,
           (written_out - i) * sizeof *pDecoded);

and then it writes `n` to the space it just made:

     pDecoded[i] = n;

if `i` is at the end of the string, then the `memmove()` has no effect because
the final parameter will be 0. The other line becomes a simple append.

Now we'll look at the three different ways that there are to get a payload 'P'
into the overflow position and why the constraints arise.

#### Method 1 - ascii overflow

The simplest way to trigger the overflow is to craft a punycode string that has
511 ascii characters in it, and two non-ascii characters. The punycode encoding
of 513-character long string such as "ÁÁAAAAAAAA...AAA"  would do. In this case
what will happen is what when `written_out` is 510 we will have a buffer laid
out as ...

    pDecoded = [ 'A' , 'A' ,  ... , 'A' , 'A',     ]
    // Indices    0     1     ...   509   510  511

this is just the basic ascii characters that have been copied in. Then we parse
the punycode bootstring and insert an `'Á'` at position 0. Though it could be
any position between 0 and 511 inclusive.

    pDecoded = [ 'Á' , 'A' ,  ... , 'A' , 'A', 'A' ]
    // Indices    0     1     ...   509   510  511

we then repeat this:

    pDecoded = [ 'Á' , 'Á' ,  ... , 'A' , 'A', 'A' ] 'A'
    // Indices    0     1     ...   509   510  511   512


this will cause the ordinary ascii 'A' to overflow as it is "moved over".  The
four byte payload in this case becomes `0x00 0x00 0x00 0x41`. As we'll see,
because of how punycode works this is the only way that any value with a final
byte in the ascii range can be expressed.

We need to use two non-ascii characters because there is a correct bounds check
on the number of basic characters, so this has to be less than 512.

An additional constraint that the final byte value can not be 46 arises because
`ossl_punycode_decode()` is called on the portion of a string that precedes a
literal `.` character. Punycode is meant for domain labels, which can't have
dots in them.

#### Method 2 - direct non-ascii overflow

The next most simple way to trigger the overflow is to craft a 513-character
string with a non-ascii character at the very end. Something like
"AAAAAAAAAA...AAÁ". In this case for our final two steps we'll have:

   pDecoded = [ 'A' , 'A' ,  ... , 'A' , 'A' ]
    // Indices    0     1     ...   510   511

and

    pDecoded = [ 'A' , 'A' ,  ... , 'A' , 'A' ] 'Á'
    // Indices    0     1     ...   510   511

the non-ascii character will go directly into the overflow position. The
OpenSSL punycode parser does not enforce that the overflow value here is
actually a valid unicode character. It's more or a less a binary decocing
process. But the nuances of punycode decoding mean that method 2 is not as
flexible as it might first appear.

In punycode the values `n` and `i` are both encoded as a single variable-length
integer that is then ascii encoded using base36. It might seem impossible to
encode two unrelated numbers as a single integer, but the clever trick punycode
has is to use the length of the string (so far) as a hidden field.

For example, suppose we have a punycode string with 4 basic characters in it,
and one non-basic, like `AAÁAA`. That will first be represented as just the
basic characters ... `AAAA`. The 'Á' unicode value is 225 and its is position
in the string 2. The trick is to multiply the value by the length plus one, and
then add the position. So it becomes ((225 * (4 +1)) + 2) which is 1127, and
that's how it's encoded (in variable length base 36).

To decode, you go the other way. 1127 / 5 is 225 and 1127 % 5 is 2. That's how
you recover two numbers from one. But notice that the longer the string gets,
you get more constrained in how big the value can be, or else the multiple
won't fit in an unsigned int. In general, if the string is M characters long
then you lose log M bits of width from the value.

By the time you are handling the 512th integer, you lose 9 bits of width. Using
method 2, the highest value a seemingly 32-bit payload could be is actually
2^23. Not even three full bytes. Method 2 is sub-optimal.

#### Method 3 - stuffing

To get back 4 bytes of control, the most efficient means is to repeat the
payload character over and over.So far I've left out two other relevant details
of how punycode is handled.

The first detail is that non-ascii characters are not encoded in string order,
but instead are encoded is ascending order of value. The string "ÉÁ" will end
up being encoded as "Á at position 1, É at position 0" because Á has a lower
value (225) than É (233).

The second detail is that non-ascii characters aren't encoded as their literal
values, but as a delta relative to the most recently decoded value. Since the
first value has no previous value to be relative to, there's a hard-coded
starting point of 128.

These little nuances make punycode very space-efficient, but also mean that a
non-ascii character simply can't be decoded to a value lower than 128. The
smallest delta is 0, and there is no way to express a negative delta. So if you
want a number less than 128, you have to use method 1.

It also means that the best strategy for as much control over the payload as
possible is to make the payload the only value in the full string, as that
way we get the full width to work with from its place at the 0th position in
the encoding. The string you encode ends up looking like;

     [ 'P', 'P', ... 'P', 'P', 'P' ]
        0    1       510  511  512

which will be decoded by OpenSSL as ...

    pDecoded = [ 'P', 'P', ... 'P', 'P' ] 'P'
                  0    1       510  511   512

with `P` in the overflow position, and capable of representing any value
between 128 and (2^32 - 1).

All of this requires a non-standard punycode encoder and I've included a
script which can craft a payload using either method 1 or method
3 as needed.

### Mini-FAQ:

**Apart from updating OpenSSL, are there other mitigations?**

Certificate Chains are passed in clear-text in most environments and a
malicious chain could be blocked by rejecting TCP connections that contain a
DER encoded `1.3.6.1.5.5.7.8.9` NID in a `SubjectAlternateName` `OtherName`
field.

Unfortunately, this field could be split arbitrarily between two or more
packets and really some kind of stateful pattern matcher is needed to block.
Certificates can also be compressed, but OpenSSL 3.0.x does not support
certificate compression at this time.

Additionally, with TLS1.3 client certificate chains are encrypted on the wire,
and prior versions of TLS support encrypted certificate chains when
renegotiating an existing connection. This is sometimes done for
server-initiated certificate authentication. A network filter will not be
effective in those cases.

**How can I tell if I'm using openssl 3 in a statically linked binary?**

     readelf -a [binary] | grep -i ossl_punycode_decode

will search for the vulnerable function in a statically-linked binary.  Only
OpenSSL >= 3.0 contains this function.

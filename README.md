signedvalue
===========

signedvalue is an implementation of signed and timestamped strings compatible with Tornado's
`create_signed_value`, `decode_signed_value`, and therefore
[set_secure_cookie](http://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler.set_secure_cookie) and
[get_secure_cookie](http://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler.get_secure_cookie).


Install
-------
```bash
go get github.com/sashka/signedvalue
```


Usage
-----
```go
import "github.com/sashka/signedvalue"

// Sign your "Hello, world".
signed := signedvalue.Encode("secret", "name", "Hello, world")

// Decode a signed string.
// Treat signed string as invalid if it's more than 1 minute old.
decoded, err := signedvalue.Decode("secret", "name", signed, 60)
if err != nil {
    // Signed string is no longer valid.
}
```


Contributing
------------
Pull requests are kindly welcome.


License
-------
The MIT License (MIT)

Copyright (c) 2018, Alexander Saltanov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

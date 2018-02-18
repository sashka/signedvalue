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
signed := signedvalue.Create("secret", "name", "Hello, world")

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

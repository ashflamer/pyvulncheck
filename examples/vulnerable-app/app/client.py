"""A plugin-style dispatcher - the receiver cannot be resolved statically.

`REGISTRY` is populated at runtime, so no static analysis can know what
`get_parser()` returns. One of the things it can return is Werkzeug's
multipart parser, which carries CVE-2023-25577.

Claiming this is safe would be a lie; claiming it is definitely exploitable
would be a false positive. pyvulncheck reports POSSIBLE and names the call
site so a human can settle it in ten seconds.
"""

from werkzeug.formparser import MultiPartParser

REGISTRY = {}


def register(name, factory):
    REGISTRY[name] = factory


def get_parser(name):
    return REGISTRY[name]


def handle(name, payload):
    parser = get_parser(name)
    return parser.parse(payload)   # which .parse()? unknowable at rest


register("multipart", MultiPartParser)

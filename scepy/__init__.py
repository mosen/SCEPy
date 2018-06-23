from flask import Flask

from .ca import CertificateAuthority
from .storage import FileStorage
from .message import SCEPMessage
from .enums import MessageType, PKIStatus, FailInfo
from .builders import PKIMessageBuilder, Signer, create_degenerate_pkcs7
from .envelope import PKCSPKIEnvelopeBuilder

# from .admin import admin_app
from .blueprint import scep_app


class WSGIChunkedBodyCopy(object):
    """WSGI wrapper that handles chunked encoding of the request body. Copies
    de-chunked body to a WSGI environment variable called `body_copy` (so best
    not to use with large requests lest memory issues crop up."""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        wsgi_input = environ.get('wsgi.input')
        if 'chunked' in environ.get('HTTP_TRANSFER_ENCODING', '') and \
                        environ.get('CONTENT_LENGTH', '') == '' and \
                wsgi_input:

            body = b''
            sz = int(wsgi_input.readline(), 16)
            while sz > 0:
                body += wsgi_input.read(sz + 2)[:-2]
                sz = int(wsgi_input.readline(), 16)

            environ['body_copy'] = body
            environ['wsgi.input'] = body

        return self.app(environ, start_response)


app = Flask(__name__)
app.config.from_object('scepy.default_settings')
app.config.from_envvar('SCEPY_SETTINGS', True)
app.wsgi_app = WSGIChunkedBodyCopy(app.wsgi_app)
# app.register_blueprint(admin_app)
app.register_blueprint(scep_app)

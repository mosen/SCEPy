from flask import Flask, abort, request, Response, g
import plistlib
from .ca import CertificateAuthority
from .storage import FileStorage
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from asn1crypto.csr import CertificationRequestInfo
from .message import SCEPMessage
from .enums import MessageType, PKIStatus, FailInfo
from .builders import PKIMessageBuilder, Signer, create_degenerate_certificate
from .envelope import PKCSPKIEnvelopeBuilder

# from .admin import admin_app

CACAPS = ('POSTPKIOperation', 'SHA-1', 'SHA-256', 'AES', 'DES3', 'SHA-512', 'Renewal')


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

with app.app_context():
    storage = FileStorage(app.config['CA_ROOT'])


@app.route('/cgi-bin/pkiclient.exe', methods=['GET', 'POST'])
@app.route('/scep', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def scep():
    op = request.args.get('operation')
    if storage.exists():
        g.ca = CertificateAuthority(storage)
    else:
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, app.config['CA_X509_CN']),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, app.config['CA_X509_O']),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, app.config['CA_X509_C'])
        ])
        g.ca = CertificateAuthority.create(storage, subject)
    ca = g.ca

    if op == 'GetCACert':
        certs = [ca.certificate]

        if len(certs) == 1 and not app.config.get('FORCE_DEGENERATE_FOR_SINGLE_CERT', False):
            return Response(certs[0].public_bytes(Encoding.DER), mimetype='application/x-x509-ca-cert')
        elif len(certs):
            raise ValueError('cryptography cannot produce degenerate pkcs7 certs')
            # p7_degenerate = degenerate_pkcs7_der(certs)
            # return Response(p7_degenerate, mimetype='application/x-x509-ca-ra-cert')
    elif op == 'GetCACaps':
        return '\n'.join(CACAPS)
    elif op == 'PKIOperation':
        if request.method == 'GET':
            msg = request.args.get('message')
            # note: OS X improperly encodes the base64 query param by not
            # encoding spaces as %2B and instead leaving them as +'s
            msg = b64decode(msg.replace(' ', '+'))
        elif request.method == 'POST':
            # workaround for Flask/Werkzeug lack of chunked handling
            if 'chunked' in request.headers.get('Transfer-Encoding', ''):
                msg = request.environ['body_copy']
            else:
                msg = request.data

        dump_request_to = app.config.get('PKCSREQ_DUMP', None)
        if dump_request_to is not None:
            app.logger.debug('Dumping request to {}'.format(dump_request_to))
            with open(dump_request_to, 'wb') as fd:
                fd.write(msg)

        req = SCEPMessage.parse(msg)
        app.logger.debug('Received SCEPMessage, details follow')
        req.debug()

        if req.message_type == MessageType.PKCSReq or req.message_type == MessageType.RenewalReq:
            app.logger.debug('received {} SCEP message'.format(MessageType(req.message_type)))

            cakey = ca.private_key
            cacert = ca.certificate

            der_req = req.get_decrypted_envelope_data(
                cacert,
                cakey,
            )

            cert_req = x509.load_der_x509_csr(der_req, backend=default_backend())
            req_info_bytes = cert_req.tbs_certrequest_bytes

            # Check the challenge password (unless it is a renewal)
            if 'SCEP_CHALLENGE' in app.config and req.message_type == MessageType.PKCSReq:
                req_info = CertificationRequestInfo.load(req_info_bytes)
                for attr in req_info['attributes']:
                    if attr['type'].native == 'challenge_password':
                        assert len(attr['values']) == 1
                        challenge_password = attr['values'][0].native
                        if challenge_password != app.config['SCEP_CHALLENGE']:
                            app.logger.warning('Client did not send the correct challenge')

                            signer = Signer(cacert, cakey)
                            reply = PKIMessageBuilder().message_type(
                                MessageType.CertRep
                            ).transaction_id(
                                req.transaction_id
                            ).pki_status(
                                PKIStatus.FAILURE, FailInfo.BadRequest
                            ).recipient_nonce(
                                req.sender_nonce
                            ).add_signer(signer).finalize()

                            return Response(reply.dump(), mimetype='application/x-pki-message')
                        else:
                            break

                    app.logger.warning('Client did not send any challenge password, but there was one configured')

                    signer = Signer(cacert, cakey)
                    reply = PKIMessageBuilder().message_type(
                        MessageType.CertRep
                    ).transaction_id(
                        req.transaction_id
                    ).pki_status(
                        PKIStatus.FAILURE, FailInfo.BadRequest
                    ).recipient_nonce(
                        req.sender_nonce
                    ).add_signer(signer).finalize()

                    return Response(reply.dump(), mimetype='application/x-pki-message')


            # CA should persist all signed certs itself
            new_cert = ca.sign(cert_req, 'sha512')
            degenerate = create_degenerate_certificate(new_cert)
            # with open('/tmp/degenerate.der', 'wb') as fd:
            #     fd.write(degenerate.dump())

            envelope, _, _ = PKCSPKIEnvelopeBuilder().encrypt(degenerate.dump(), 'aes256').add_recipient(
                req.certificates[0]).finalize()
            signer = Signer(cacert, cakey, 'sha512')

            reply = PKIMessageBuilder().message_type(
                MessageType.CertRep
            ).transaction_id(
                req.transaction_id
            ).pki_status(
                PKIStatus.SUCCESS
            ).recipient_nonce(
                req.sender_nonce
            ).pki_envelope(
                envelope
            ).certificates(new_cert).add_signer(signer).finalize()

            # res = SCEPMessage.parse(reply.dump())
            # app.logger.debug('Reply with CertRep, details follow')
            # res.debug()

            # with open('/tmp/reply.bin', 'wb') as fd:
            #     fd.write(reply.dump())

            return Response(reply.dump(), mimetype='application/x-pki-message')
        else:
            app.logger.error('unhandled SCEP message type: %d', req.message_type)
            return ''
    else:
        abort(404, 'unknown SCEP operation')


@app.route('/mobileconfig')
def mobileconfig():
    """Quick and dirty SCEP enrollment mobileconfiguration profile."""
    my_url = 'http://localhost:5000'

    profile = {
        'PayloadType': 'Configuration',
        'PayloadDisplayName': 'SCEPy Enrolment Profile',
        'PayloadDescription': 'This profile will enroll your device with the SCEP server',
        'PayloadVersion': 1,
        'PayloadIdentifier': 'com.github.mosen.scepy',
        'PayloadUUID': '7F165A7B-FACE-4A6E-8B56-CA3CC2E9D0BF',
        'PayloadContent': [
            {
                'PayloadType': 'com.apple.security.scep',
                'PayloadVersion': 1,
                'PayloadIdentifier': 'com.github.mosen.scepy.scep',
                'PayloadUUID': '16D129CA-DA22-4749-82D5-A28201622555',
                'PayloadDisplayName': 'SCEPy Enrolment Payload',
                'PayloadDescription': 'SCEPy Enrolment Payload',
                'PayloadContent': {
                    'URL': my_url,
                    'Name': 'SCEPY-CA',
                    'Keysize': 2048,
                    'Key Usage': 5
                }
            }
        ]
    }

    return plistlib.dumps(profile), {'Content-Type': 'application/x-apple-aspen-config'}

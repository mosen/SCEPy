import os
import datetime
from base64 import b64decode
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from asn1crypto.csr import CertificationRequestInfo
from flask import Blueprint, abort, g, current_app, request, Response, url_for
import plistlib

from .message import SCEPMessage
from .ca import CertificateAuthority
from .storage import FileStorage
from .enums import MessageType, PKIStatus, FailInfo
from .builders import PKIMessageBuilder, Signer, create_degenerate_pkcs7
from .envelope import PKCSPKIEnvelopeBuilder

scep_app = Blueprint('scep_app', __name__)

CACAPS = ('POSTPKIOperation', 'SHA-1', 'SHA-256', 'AES', 'DES3', 'SHA-512', 'Renewal')


@scep_app.route('/', methods=['GET', 'POST'])
@scep_app.route('/cgi-bin/pkiclient.exe', methods=['GET', 'POST'])
@scep_app.route('/scep', methods=['GET', 'POST'])
def scep():
    storage = FileStorage(current_app.config['SCEPY_CA_ROOT'])
    op = request.args.get('operation')
    current_app.logger.info("Operation: %s, From: %s, User-Agent: %s", op, request.remote_addr, request.user_agent)

    dump_dir = current_app.config.get('SCEPY_DUMP_DIR', None)
    if dump_dir is not None and not os.path.exists(dump_dir):
        current_app.logger.debug("Creating dir for request dumps: %s", dump_dir)
        os.mkdir(dump_dir)

    dump_filename_prefix = "request-{}".format(datetime.datetime.now().timestamp())

    if storage.exists():
        g.ca = CertificateAuthority(storage)
    else:
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, current_app.config['SCEPY_CA_X509_CN']),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, current_app.config['SCEPY_CA_X509_O']),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, current_app.config['SCEPY_CA_X509_C'])
        ])
        g.ca = CertificateAuthority.create(storage, subject)
    ca = g.ca

    if op == 'GetCACert':
        certs = [ca.certificate]

        if len(certs) == 1 and not current_app.config.get('SCEPY_FORCE_DEGENERATE_FOR_SINGLE_CERT', False):
            return Response(certs[0].public_bytes(Encoding.DER), mimetype='application/x-x509-ca-cert')
        elif len(certs):
            raise ValueError('cryptography cannot produce degenerate pkcs7 certs')
            # p7_degenerate = degenerate_pkcs7_der(certs)
            # return Response(p7_degenerate, mimetype='application/x-x509-ca-ra-cert')
    elif op == 'GetCACaps':
        return Response('\n'.join(CACAPS), mimetype='text/plain')

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

        if dump_dir is not None:
            filename = "{}.bin".format(dump_filename_prefix)
            current_app.logger.debug('Dumping request to {}'.format(os.path.join(dump_dir, filename)))
            with open(os.path.join(dump_dir, filename), 'wb') as fd:
                fd.write(msg)

        req = SCEPMessage.parse(msg)
        current_app.logger.debug('Message Type: %s', req.message_type)
        print(req.debug())

        if req.message_type == MessageType.PKCSReq or req.message_type == MessageType.RenewalReq:
            cakey = ca.private_key
            cacert = ca.certificate

            der_req = req.get_decrypted_envelope_data(
                cacert,
                cakey,
            )

            if dump_dir is not None:
                filename = os.path.join(dump_dir, '{}.csr'.format(dump_filename_prefix))
                current_app.logger.debug('Dumping CertificateSigningRequest to {}'.format(os.path.join(dump_dir, filename)))
                with open(filename, 'wb') as fd:
                    fd.write(der_req)

            cert_req = x509.load_der_x509_csr(der_req, backend=default_backend())
            req_info_bytes = cert_req.tbs_certrequest_bytes

            # Check the challenge password (unless it is a renewal)
            if 'SCEPY_CHALLENGE' in current_app.config and req.message_type == MessageType.PKCSReq:
                req_info = CertificationRequestInfo.load(req_info_bytes)
                for attr in req_info['attributes']:
                    if attr['type'].native == 'challenge_password':
                        assert len(attr['values']) == 1
                        challenge_password = attr['values'][0].native
                        if challenge_password != current_app.config['SCEPY_CHALLENGE']:
                            current_app.logger.warning('Client did not send the correct challenge')

                            signer = Signer(cacert, cakey, 'sha512')
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
                            current_app.logger.debug('Client sent correct challenge')
                            break

                    current_app.logger.warning(
                        'Client did not send any challenge password, but there was one configured')

                    signer = Signer(cacert, cakey, 'sha1')
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

            new_cert = ca.sign(cert_req, 'sha1')
            degenerate = create_degenerate_pkcs7(new_cert, ca.certificate)

            if dump_dir is not None:
                filename = os.path.join(dump_dir, '{}-degenerate.bin'.format(dump_filename_prefix))
                with open(filename, 'wb') as fd:
                    fd.write(degenerate.dump())

            envelope, _, _ = PKCSPKIEnvelopeBuilder().encrypt(degenerate.dump(), 'aes256').add_recipient(
                req.certificates[0]).finalize()
            signer = Signer(cacert, cakey, 'sha1')

            reply = PKIMessageBuilder().message_type(
                MessageType.CertRep
            ).transaction_id(
                req.transaction_id
            ).pki_status(
                PKIStatus.SUCCESS
            ).recipient_nonce(
                req.sender_nonce
            ).sender_nonce().pki_envelope(
                envelope
            ).add_signer(signer).finalize()

            if dump_dir is not None:
                filename = os.path.join(dump_dir, '{}-reply.bin'.format(dump_filename_prefix))
                with open(filename, 'wb') as fd:
                    fd.write(reply.dump())

            current_app.logger.debug("Sending CertRep")
            return Response(reply.dump(), mimetype='application/x-pki-message')
        else:
            current_app.logger.error('unhandled SCEP message type: %d', req.message_type)
            return ''
    else:
        abort(404, 'unknown SCEP operation')


@scep_app.route('/mobileconfig')
def mobileconfig():
    """Quick and dirty SCEP enrollment mobileconfiguration profile."""
    my_url = url_for('scep_app.scep', _external=True)

    profile = {
        'PayloadType': 'Configuration',
        'PayloadDisplayName': 'SCEPy Enrolment Test Profile',
        'PayloadDescription': 'This profile will enroll your device with the SCEP server',
        'PayloadVersion': 1,
        'PayloadIdentifier': 'com.github.cmdmnt.scepy',
        'PayloadUUID': '7F165A7B-FACE-4A6E-8B56-CA3CC2E9D0BF',
        'PayloadContent': [
            {
                'PayloadType': 'com.apple.security.scep',
                'PayloadVersion': 1,
                'PayloadIdentifier': 'com.github.cmdmnt.scepy.scep',
                'PayloadUUID': '16D129CA-DA22-4749-82D5-A28201622555',
                'PayloadDisplayName': 'SCEPy Test Enrolment Payload',
                'PayloadDescription': 'SCEPy Test Enrolment Payload',
                'PayloadContent': {
                    'URL': my_url,
                    'Name': 'SCEPY',
                    'Keysize': 2048,
                    'Key Usage': 5
                }
            }
        ]
    }

    if 'SCEPY_CHALLENGE' in current_app.config:
        profile['PayloadContent'][0]['PayloadContent']['Challenge'] = current_app.config['SCEPY_CHALLENGE']

    return plistlib.dumps(profile), {'Content-Type': 'application/x-apple-aspen-config'}


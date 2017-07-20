import argparse
import logging

from typing import List, Set
from ..builders import PKIMessageBuilder, Signer
from ..envelope import PKCSPKIEnvelopeBuilder
import requests
from .request import generate_csr, generate_self_signed
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from ..enums import MessageType, PKIStatus, FailInfo, CACaps
from cryptography.hazmat.backends import default_backend
from ..message import SCEPMessage
from asn1crypto.cms import ContentInfo, CertificateSet
from asn1crypto import x509 as asn1x509
from cryptography.x509.oid import NameOID

parser = argparse.ArgumentParser()
parser.add_argument('url', help='The SCEP server URL')
parser.add_argument('operation', help='The operation to perform', default='pkcsreq', choices=['pkcsreq', 'getcert'])
parser.add_argument('-v', '--verbose', action='count', default=0)
parser.add_argument('-c', '--challenge', help='SCEP Challenge to send with the signing request')
parser.add_argument('-k', '--private-key', help='PEM formatted RSA private key (will be generated if omitted)')
parser.add_argument('-p', '--password', help='private key password (if required)')
parser.add_argument('--dump-request', help='dump binary representation of PKCSReq to this location')
parser.add_argument('--dump-response', help='dump binary representation of CertRep to this location')

logger = logging.getLogger(__name__)


def certificates_from_asn1(cert_set: CertificateSet) -> List[x509.Certificate]:
    """Convert an asn1crypto CertificateSet to a list of cryptography.x509.Certificate."""
    result = list()

    for cert in cert_set:
        cert_choice = cert.chosen
        assert isinstance(cert_choice, asn1x509.Certificate)  # Can't handle any other type
        result.append(x509.load_der_x509_certificate(cert_choice.dump(), default_backend()))

    return result


def getcacaps(url: str) -> Set[CACaps]:
    """Query the SCEP Service for its capabilities."""
    res = requests.get(url, {'operation': 'GetCACaps'})
    if res.status_code != 200:
        raise ValueError('Got invalid status code for GetCACaps: {}'.format(res.status_code))
    caps = res.text.split("\n")
    cacaps = {CACaps(cap.strip()) for cap in caps}
    return cacaps


def getcacert(url: str) -> List[x509.Certificate]:
    """Query the SCEP Service for the CA Certificate."""
    res = requests.get(url, {'operation': 'GetCACert'})
    assert res.status_code == 200
    if res.headers['content-type'] == 'application/x-x509-ca-cert':  # we dont support RA cert yet
        return [x509.load_der_x509_certificate(res.content, default_backend())]
    elif res.headers['content-type'] == 'application/x-x509-ca-ra-cert':  # intermediate via chain
        ci = ContentInfo.load(res.content)
        #  print(ci['content_type'].native)
        assert ci['content_type'].native == 'signed_data'
        signed_data = ci['content']
        # convert certificates using cryptography lib since it is easier to deal with the decryption
        assert len(signed_data['certificates']) > 0
        certs = certificates_from_asn1(signed_data['certificates'])
        return certs


def pkioperation(url: str, data: bytes):
    """Perform a PKIOperation using the CMS data given."""
    res = requests.post('{}?operation=PKIOperation'.format(url), data=data,
                        headers={'content-type': 'application/x-pki-message'})
    return res


def pkcsreq(url: str, private_key_path: str = None):
    """Perform a PKCSReq operation by submitting a CSR to the SCEP service."""

    logger.info('Request: GetCACaps')
    cacaps = getcacaps(url)
    logger.debug(cacaps)
    logger.info('Request: GetCACert')
    ca_certificates = getcacert(url)
    logger.debug('CA Certificate Subject(s) Follows')
    for c in ca_certificates:
        logger.debug(c.subject)

    if private_key_path:
        with open(private_key_path, 'rb') as fd:
            data = fd.read()
            private_key = serialization.load_pem_private_key(data, backend=default_backend(), password=None)

        logger.debug('Successfully read private key from filesystem')
        private_key, csr = generate_csr(private_key)
    else:
        private_key, csr = generate_csr()

        logger.debug('Writing RSA private key to ./scep.key')
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open('scep.key', 'wb') as fd:
            fd.write(pem)

    ssc = generate_self_signed(private_key, x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'SCEPy SCEP SIGNER'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    ]))

    envelope = PKCSPKIEnvelopeBuilder().encrypt(
        csr.public_bytes(serialization.Encoding.DER), '3des'
    )

    envelope.add_recipient(ca_certificates[1])
    # for recipient in ca_certificates:
    #     envelope = envelope.add_recipient(recipient)

    envelope, key, iv = envelope.finalize()

    with open('scepyclient.csr', 'wb') as fd:
        fd.write(csr.public_bytes(serialization.Encoding.DER))

    signer = Signer(ssc, private_key, 'sha512')

    pki_msg_builder = PKIMessageBuilder().message_type(
        MessageType.PKCSReq
    ).pki_envelope(
        envelope
    ).add_signer(
        signer
    ).transaction_id().sender_nonce()

    pki_msg = pki_msg_builder.finalize()

    # if args.dump_request:
    #     with open(args.dump_pkcsreq, 'wb') as fd:
    #         fd.write(pki_msg.dump())
    #     logger.debug('Dumped PKCSReq data to {}'.format(args.dump_pkcsreq))

    with open('scepyclient-request.bin', 'wb') as fd:
        fd.write(pki_msg.dump())


    res = pkioperation(url, data=pki_msg.dump())

    logger.debug('Response: Status {}'.format(res.status_code))
    if res.status_code != 200:
        return -1
    #
    # with open('ndes-response.bin', 'wb') as fd:


    cert_rep = SCEPMessage.parse(res.content)
    # if args.dump_response:
    #     with open(args.dump_response, 'wb') as fd:
    #         fd.write(res.content)
    #     logger.debug('Dumped CertRep data to {}'.format(args.dump_response))

    logger.debug('pkiMessage response follows')
    logger.debug('Transaction ID: %s', cert_rep.transaction_id)
    logger.debug('PKI Status: %s', PKIStatus(cert_rep.pki_status))

    if PKIStatus(cert_rep.pki_status) == PKIStatus.FAILURE:
        logger.error('SCEP Request Failed: {}'.format(FailInfo(cert_rep.fail_info)))

    elif PKIStatus(cert_rep.pki_status) == PKIStatus.SUCCESS:
        # This should be the PKCS#7 Degenerate
        decrypted_bytes = cert_rep.get_decrypted_envelope_data(ssc, private_key)
        degenerate_info = ContentInfo.load(decrypted_bytes)
        degenerate_info.debug()

        assert degenerate_info['content_type'].native == 'signed_data'
        signed_response = degenerate_info['content']
        certs = signed_response['certificates']

        my_cert = certs[0].chosen

        result = x509.load_der_x509_certificate(my_cert.dump(), default_backend())
        subject = result.subject

        logger.info('SCEP CA issued a certificate with serial #{}, subject: {}'.format(result.serial_number, subject))

        pem_data = result.public_bytes(serialization.Encoding.PEM)
        with open('scep.cer', 'wb') as fd:
            fd.write(pem_data)


def main():
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)

    if args.operation == 'pkcsreq':
        pkcsreq(args.url)
    elif args.operation == 'getcert':
        pass
    




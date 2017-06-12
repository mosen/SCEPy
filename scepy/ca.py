from flask import g, current_app
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from .abcs import CertificateAuthorityStorage

from asn1crypto.cms import SignerIdentifier, IssuerAndSerialNumber


class CertificateAuthority(object):
    """The CertificateAuthority Class implements a basic Cert Authority.
    
    It is recommended to use an external CA if possible.
    """

    default_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'SCEPY-CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'SCEPy'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')
    ])

    @classmethod
    def create(cls, storage: CertificateAuthorityStorage, subject: x509.Name = default_subject, key_size: int = 2048,
               validity_period: datetime.timedelta = datetime.timedelta(days=365)):
        """Create and persist a Certificate Authority using the given storage backend.
        
        Args:
              storage (CertificateAuthorityStorage): The storage backend to persist the CA key and certificates.
              subject (x509.Name): The subject of the CA certificate.
              key_size (int): The RSA Private key size in bits, default is 2048
              validity_period (timedelta): The timedelta indicating the number of days validity to add to the current
                date.
                
        Returns:
              CertificateAuthority
        """

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        storage.private_key = private_key
        
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + validity_period
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            True
        ).add_extension(
            #  Absolutely critical for SCEP
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            True
        ).sign(private_key, hashes.SHA512(), default_backend())  # Was: SHA-256 for macOS

        storage.ca_certificate = certificate

        ca = cls(storage)
        return ca

    def __init__(self, storage: CertificateAuthorityStorage):
        """
        Args:
            storage (CertificateAuthorityStorage): The storage backend to persist keys and certificates.
        """
        self._storage = storage

    @property
    def serial(self):
        return self._storage.serial

    @serial.setter
    def serial(self, value: int):
        self._storage.serial = value

    @property
    def certificate(self) -> x509.Certificate:
        """Retrieve the CA Certificate"""
        return self._storage.ca_certificate

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Retrieve the CA Private Key"""
        return self._storage.private_key

    def signer_identifier(self) -> SignerIdentifier:
        """Get the identity of this CA instance as a SignerIdentifier structure for CMS."""
        ias = IssuerAndSerialNumber()
        #ias['issuer'] = self.certificate.issuer  # probably wont work, need to get the asn1crypto type
        ias['serial_number'] = self.certificate.serial_number
        sid = SignerIdentifier('issuer_and_serial_number', ias)

        return sid

    def sign(self, csr: x509.CertificateSigningRequest, algorithm: str = 'sha256') -> x509.Certificate:
        """Sign a certificate signing request.

        Args:
            csr (x509.CertificateSigningRequest): The certificate signing request
        Returns:
            Instance of x509.Certificate
        """
        serial = self.serial + 1
        builder = x509.CertificateBuilder()

        hash_functions = {
            'sha1': hashes.SHA1,
            'sha256': hashes.SHA256,
            'sha512': hashes.SHA512,
        }

        cert = builder.subject_name(
            csr.subject
        ).issuer_name(
            self.certificate.subject
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).serial_number(
            serial
        ).public_key(
            csr.public_key()
        ).sign(self.private_key, hash_functions.get(algorithm, hashes.SHA256)(), default_backend())

        self._storage.save_issued_certificate(cert)
        self.serial = serial

        return cert


def get_ca() -> CertificateAuthority:
    ca = getattr(g, '_mdm_ca', None)
    if ca is None:
        ca = g._mdm_ca = ca_from_storage(current_app.config['CA_ROOT'])
    return ca

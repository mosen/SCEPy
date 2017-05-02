from typing import Union
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from scepy import models
from .abcs import CertificateAuthorityStorage
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


class FileStorage(CertificateAuthorityStorage):
    """FileStorage implements a filesystem based certificate authority storage.
    
    Args:
          base_path (str): The root directory of the Certificate Authority where all items will be stored.
          password (Union[None, str]): Optional. The RSA Private Key password
    """

    def __init__(self, base_path: str, password: Union[None, str] = None):
        if not os.path.exists(base_path):
            os.mkdir(base_path)
            
        self._base_path = base_path

        for p in ['private', 'certs', 'newcerts']:
            if not os.path.exists(os.path.join(base_path, p)):
                os.mkdir(os.path.join(base_path, p))
                
        self._key_path = os.path.join(base_path, 'private', 'ca.key.pem')
        self._cert_path = os.path.join(base_path, 'certs', 'ca.cer')
        self._issued_path = os.path.join(base_path, 'newcerts')
        self._serial_path = os.path.join(base_path, 'private', 'serial.txt')
        self._password = password

    def exists(self) -> bool:
        return os.path.exists(self._key_path) and os.path.exists(self._cert_path)

    @property
    def ca_certificate(self) -> Union[None, x509.Certificate]:
        if not os.path.exists(self._cert_path):
            return None

        with open(self._cert_path, 'rb') as fd:
            pem_data = fd.read()

        certificate = x509.load_der_x509_certificate(
            data=pem_data,
            backend=default_backend()
        )

        return certificate

    @ca_certificate.setter
    def ca_certificate(self, certificate: x509.Certificate):
        pem_data = certificate.public_bytes(serialization.Encoding.PEM)

        with open(self._cert_path, 'wb') as fd:
            fd.write(pem_data)

    @property
    def private_key(self) -> Union[None, rsa.RSAPrivateKey]:
        if not os.path.exists(self._key_path):
            return None

        with open(self._key_path, 'rb') as key_file:
            data = key_file.read()

        private_key = serialization.load_pem_private_key(
            data=data,
            password=self._password,
            backend=default_backend()
        )

        return private_key

    @private_key.setter
    def private_key(self, private_key: rsa.RSAPrivateKey):
        if self._password is not None:
            enc = serialization.BestAvailableEncryption(self._password)
        else:
            enc = serialization.NoEncryption()

        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        )

        with open(os.path.join(self._key_path), 'wb') as fd:
            fd.write(key_bytes)

    @property
    def serial(self) -> int:
        return 1  # TODO: READ

    @serial.setter
    def serial(self, no: int):
        with open(self._serial_path, 'w+') as fd:
            fd.write(str(no))

    def save_issued_certificate(self, certificate: x509.Certificate):
        cert_path = os.path.join(self._issued_path, '{}.cer'.format(certificate.serial_number))
        with open(cert_path, 'wb') as fd:
            fd.write(certificate.public_bytes(serialization.Encoding.PEM))

    def fetch_issued_certificate(self, serial: int) -> Union[None, x509.Certificate]:
        cert_path = os.path.join(self._issued_path, '{}.cer'.format(serial))
        with open(cert_path, 'rb') as fd:
            pem_data = fd.read()

        certificate = x509.load_pem_x509_certificate(
            data=pem_data,
            backend=default_backend()
        )
        return certificate


class SQLAlchemyStorage(CertificateAuthorityStorage):
    """SQLAlchemyStorage implements a database driven Certificate Authority storage."""

    def __init__(self, db):
        self._db = db

    @property
    def ca_certificate(self) -> Union[None, x509.Certificate]:
        pass
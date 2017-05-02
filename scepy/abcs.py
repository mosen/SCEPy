from typing import Union
from abc import ABCMeta, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


class CertificateAuthorityStorage(object):
    __metaclass__ = ABCMeta

    @property
    @abstractmethod
    def private_key(self) -> Union[None, rsa.RSAPrivateKey]:
        """Retrieve the RSA Private key (If available)"""
        pass

    @private_key.setter
    @abstractmethod
    def private_key(self, private_key: rsa.RSAPrivateKey):
        pass

    @property
    @abstractmethod
    def ca_certificate(self) -> Union[None, x509.Certificate]:
        """Retrieve the CA Certificate (If available)"""
        pass

    @ca_certificate.setter
    @abstractmethod
    def ca_certificate(self, certificate: x509.Certificate):
        pass

    @property
    @abstractmethod
    def serial(self) -> int:
        """Retrieve the CURRENT serial number (not the next available)."""
        pass

    @serial.setter
    @abstractmethod
    def serial(self, no: int):
        """Set the CURRENT serial number (not the next available)."""
        pass

    @abstractmethod
    def exists(self) -> bool:
        """Does a CA already exist with this storage type?"""
        pass

    @abstractmethod
    def save_issued_certificate(self, certificate: x509.Certificate):
        """Save a certificate that was issued by the CA."""
        pass

    @abstractmethod
    def fetch_issued_certificate(self, serial: int) -> x509.Certificate:
        """Retrieve a certificate that was issued by the CA."""
        pass

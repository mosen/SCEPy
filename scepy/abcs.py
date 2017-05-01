from typing import Union
from abc import ABCMeta, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


class CertificateAuthorityStorage(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    @property
    def private_key(self) -> Union[None, rsa.RSAPrivateKey]:
        """Retrieve the RSA Private key (If available)"""
        pass

    @abstractmethod
    @private_key.setter
    def private_key(self, private_key: rsa.RSAPrivateKey):
        pass

    @abstractmethod
    @property
    def ca_certificate(self) -> Union[None, x509.Certificate]:
        """Retrieve the CA Certificate (If available)"""
        pass

    @abstractmethod
    @ca_certificate.setter
    def ca_certificate(self, certificate: x509.Certificate):
        pass

    @abstractmethod
    @property
    def serial(self) -> int:
        """Retrieve the CURRENT serial number (not the next available)."""
        pass

    @abstractmethod
    @serial.setter
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

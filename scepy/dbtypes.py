import sqlalchemy.types as types
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class DERCertificate(types.TypeDecorator):
    """Marshals certificate data to and from DER encoded LargeBinary/BLOB columns."""

    impl = types.LargeBinary

    def process_bind_param(self, value: x509.Certificate, dialect):
        return value.public_bytes(serialization.Encoding.DER)

    def process_result_value(self, value: bytes, dialect):
        return x509.load_der_x509_certificate(value, default_backend())

    def copy(self, **kw):
        return DERCertificate()


class DERPrivateKey(types.TypeDecorator):
    """Marshal RSA Private Key to and from LargeBinary."""

    impl = types.LargeBinary

    def process_bind_param(self, value: rsa.RSAPrivateKeyWithSerialization, dialect):
        return value.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def process_result_value(self, value: bytes, dialect):
        return serialization.load_der_private_key(value, None, default_backend())

    def copy(self, **kw):
        return DERPrivateKey()


class DERSigningRequest(types.TypeDecorator):
    """Marshals certificate data to and from DER encoded LargeBinary/BLOB columns."""

    impl = types.LargeBinary

    def process_bind_param(self, value: x509.CertificateSigningRequest, dialect):
        return value.public_bytes(serialization.Encoding.DER)

    def process_result_value(self, value: bytes, dialect) -> x509.CertificateSigningRequest:
        return x509.load_der_x509_csr(value, default_backend())

    def copy(self, **kw):
        return DERSigningRequest()


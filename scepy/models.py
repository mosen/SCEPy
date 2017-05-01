from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, Text, String, DateTime, Enum
from sqlalchemy.orm import relationship
from datetime import datetime

from scepy.dbtypes import DERCertificate, DERPrivateKey, DERSigningRequest
from scepy.enums import RevocationReason

db = SQLAlchemy()


class RSAPrivateKey(db.Model):
    id = Column(Integer, primary_key=True)
    der_data = Column(DERPrivateKey, nullable=False)
    password = Column(String)  # Yeah, this is super insecure

    created_at = Column(DateTime, default=datetime.utcnow())


class CertificateSigningRequest(db.Model):
    id = Column(Integer, primary_key=True)
    der_data = Column(DERSigningRequest, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow())


class Certificate(db.Model):
    serial = Column(Integer, primary_key=True)
    der_data = Column(DERCertificate, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow())

    signing_request = relationship(
        'CertificateSigningRequest',
        backref='certificate'
    )


class RevokedCertificate(db.Model):
    id = Column(Integer, primary_key=True)
    revocation_date = Column(DateTime, default=datetime.utcnow())
    reason = Column(Enum(RevocationReason))
    

class CertificateAuthority(db.Model):
    id = Column(Integer, primary_key=True)
    
    x509_cn = Column(String(64), nullable=False)
    x509_ou = Column(String(32))
    x509_o = Column(String(64))
    x509_c = Column(String(2))
    x509_st = Column(String(128))

    san_dnsname = Column(String)
    san_ipaddr = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow())

    certificate = relationship(
        'Certificate',
        backref='certificate_authority'
    )

    rsa_private_key = relationship(
        'RSAPrivateKey',
        backref='certificate_authority'
    )


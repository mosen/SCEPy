# Flask based settings
DEBUG = True

# Directory where certs, revocation lists, serials etc will be kept
SCEPY_CA_ROOT = "/tmp/ca"

# X.509 Name Attributes used to generate the CA Certificate
SCEPY_CA_X509_CN = 'SCEPY-CA'
SCEPY_CA_X509_O = 'SCEPy'
SCEPY_CA_X509_C = 'AU'

# SubjectAltName extension is always on and will use this DNSName
SAN_DNSNAME = 'scepy.dev'

# Listen port
PORT = 5000

# (Optional) SCEP static challenge
# SCEP_CHALLENGE = 'sekret'


SCEPY_FORCE_DEGENERATE_FOR_SINGLE_CERT = False

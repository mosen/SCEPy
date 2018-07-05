import sys
import os.path
from asn1crypto.cms import SignedData, ContentInfo
from scepy import asn1
from asn1crypto.cms import CMSAttribute

CMSAttribute._fields = [
    ('type', asn1.SCEPCMSAttributeType),
    ('values', None),
]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(1)

    with open(sys.argv[1], 'rb') as fd:
        content = ContentInfo.load(fd.read())
        content.debug()

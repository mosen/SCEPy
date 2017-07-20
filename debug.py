from asn1crypto.cms import ContentInfo

with open('./scepyclient-request.bin', 'rb') as fd:
    content = ContentInfo.load(fd.read())
    content.debug()
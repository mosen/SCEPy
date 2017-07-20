from asn1crypto.cms import ContentInfo

with open('./degenerate.bin', 'rb') as fd:
    content = ContentInfo.load(fd.read())
    content.debug()
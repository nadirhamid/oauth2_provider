class BaseToken(object):
    pass

class BearerToken(BaseToken):
    """
    http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-22

     GET /resource HTTP/1.1
     Host: server.example.com
     Authorization: Bearer mF_9.B5f-4.1JqM

     The "Authorization" header field uses the framework defined by
     HTTP/1.1 [RFC2617] as follows:

     b64token    = 1*( ALPHA / DIGIT /
                       "-" / "." / "_" / "~" / "+" / "/" ) *"="

     credentials = "Bearer" 1*SP b64token
    """
    pass

class HMACToken(BaseToken):
    """
    http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
    """
    pass

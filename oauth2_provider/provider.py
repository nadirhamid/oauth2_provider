from .utils import gen_api_key
from .utils import clean_url

class BaseProvider(object):
    """ 
    This is the base Provider class for OAuth2 Specification

    This flow is:

     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+

    1. verify_auth_request
    2. verify_auth_token
    """

    @property
    def token_length(self):
        """
        The length of a generated token
        """
        return 32

    @property
    def token_type(self):
        """
        The type of access token we are using
        """
        return 'Bearer'

    @property
    def token_expires_in(self):
        """
        How long until the access token expires

        defaults to 10 minutes
        """
        return 60 * 10 * 10

    def generate_authorization_code(self):
        """Generate a random authorization code."""
        return gen_api_key(length=self.token_length)

    def generate_access_token(self):
        """Generate a random access token."""
        return gen_api_key(length=self.token_length)

    def generate_refresh_token(self):
        """Generate a random refresh token."""
        return gen_api_key(length=self.token_length)

    def response_error(self, error, error_description=None, error_uri=None,
        redirect_uri=None, state=None):
        data = {'error': error}

        if redirect_uri:
            data['redirect_uri'] = redirect_uri

        if error_uri:
            data['error_uri'] = error_uri

        if error_description:
            data['error_description'] = error_description

        if state:
            data['state'] = state

        return data


    def invalid_request(self, **kwargs):
        kwargs['error_description'] = """The request is missing a required
            parameter, includes an invalid parameter value, includes a
            parameter more than once, or is otherwise malformed.
            """
        return self.response_error('invalid_request', **kwargs)


    def unsupported_response_type(self, **kwargs):
        kwargs['error_description'] = """
            The authorization server does not support obtaining an
            authorization code using this method.
            """
        return self.response_error('unsupported_response_type', **kwargs)


    def access_denied(self, **kwargs):
        kwargs['error_description'] = """
            The resource owner or authorization server denied the request.
            """

        return self.response_error('access_denied', **kwargs)


    def invalid_scope(self, **kwargs):
        kwargs['error_description'] = """
            The requested scope is invalid, unknown, or malformed.
            """
        return self.response_error('invalid_scope', **kwargs)
    
    def unauthorized_client(self, **kwargs):
        kwargs['error_description'] = """
            The client is not authorized to request an authorization
            code using this method.
            """
        return self.response_error('unauthorized_client', **kwargs)


class AuthorizationProvider(BaseProvider):
    def verify_auth_request(self, response_type, client_id, **kwargs):
        """
        This will handle the spec 4.1.2 (Authorization Request),
        and 4.1.2.1 (Error Response).

        PARAMETERS:
        response_type
                REQUIRED.  Value MUST be set to "code".

        client_id
                REQUIRED.  The client identifier as described in Section 2.2.

        redirect_uri
                OPTIONAL.  As described in Section 3.1.2.

        scope
                OPTIONAL.  The scope of the access request as described by
                Section 3.3.
        state
                RECOMMENDED.  An opaque value used by the client to maintain
                state between the request and callback.  The authorization
                server includes this value when redirecting the user-agent back
                to the client.  The parameter SHOULD be used for preventing
                cross-site request forgery as described in Section 10.12.


        If the resource owner grants the access request, the authorization
        server issues an authorization code and delivers it to the client by
        adding the following parameters to the query component of the
        redirection URI using the "application/x-www-form-urlencoded" format,
        per Appendix B:

        code
                REQUIRED.  The authorization code generated by the
                authorization server.  The authorization code MUST expire
                shortly after it is issued to mitigate the risk of leaks.  A
                maximum authorization code lifetime of 10 minutes is
                RECOMMENDED.  The client MUST NOT use the authorization code
                more than once.  If an authorization code is used more than
                once, the authorization server MUST deny the request and SHOULD
                revoke (when possible) all tokens previously issued based on
                that authorization code.  The authorization code is bound to
                the client identifier and redirection URI.
        state
                REQUIRED if the "state" parameter was present in the client
                authorization request.  The exact value received from the
                client.
        """
        redirect_uri = kwargs.pop('redirect_uri', None)
        scope = kwargs.pop('scope', None)
        state = kwargs.pop('state', None)

        if not client_id or not response_type:
            return self.invalid_request(
                redirect_uri = redirect_uri
                , state = state
            )

        is_client_id_valid = self.verify_client_id(client_id)

        if not is_client_id_valid:
            return self.unauthorized_client(
                redirect_uri = redirect_uri
                , state = state
            )


        if redirect_uri == None:
            redirect_uri = self.get_redirect_uri(client_id)

        is_redirect_uri_valid = self.verify_redirect_uri(client_id,
                redirect_uri)

        if not is_redirect_uri_valid:
            return self.invalid_request()

        if response_type != 'code':
            return self.unsupported_response_type(
                redirect_uri = redirect_uri
                , state = state
            )

        is_scope_valid = self.verify_scope(scope)

        if not is_scope_valid:
            return self.invalid_scope(
                redirect_uri = redirect_uri
                , state = state
            )

        code = self.generate_authorization_code()

        # Save information to be used to validate later requests
        self.save_data(
            client_id
            , code
            , scope
            , redirect_uri
        )

        new_qs = {'code': code}

        if state:
            new_qs['state'] = state

        return {'redirect_uri': clean_url(redirect_uri, new_qs)}

    def save_data(self, client_id, code, scope, redirect_uri):
        """ This persists the authorized data to a datastore for
        checking against on the next request
        """
        raise NotImplementedError(
            """
                save_data must be implemented by a child class
            """
        )


    def verify_client_id(self, client_id):
        """ This validates that the client id being requested is a valid
        client in your datastore

        Should return True or False
        """
        raise NotImplementedError(
            """
                verify_client_id must be implemented by a child class
            """
        )

    def verify_scope(self, client_id, scope):
        """ This validates that the scope being requested is valid for your
        application, return self.invalid_scope if it is not valid

        Should return True or False
        """
        raise NotImplementedError(
            """
                verify_scope must be implemented by a child class
            """
        )

    def verify_redirect_uri(self, client_id, redirect_uri):
        """ This validates that the redirect_uri provided is registered to the
        client in your datastore

        Should return True or False
        """
        raise NotImplementedError(
            """
                verify_redirect_uri must be implemented by a child class
            """
        )

    def get_redirect_uri(self, client_id):
        """
            This gets the redirect_uri defined at app registration
        """
        raise NotImplementedError(
            """
                get_redirect_uri must be implemented by a child class
            """
        )

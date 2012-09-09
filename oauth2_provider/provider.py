from .utils import gen_api_key
from .utils import clean_url
from .utils import get_query_string

class BaseProvider(object):
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

        defaults to 1 hour
        """
        return 60 * 60

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
        error_description = kwargs.pop('error_description',
            """The request is missing a required
            parameter, includes an invalid parameter value, includes a
            parameter more than once, or is otherwise malformed.
            """
        )

        kwargs['error_description'] = error_description

        return self.response_error('invalid_request', **kwargs)


    def unsupported_response_type(self, **kwargs):
        error_description = kwargs.pop('error_description',
            """
            The authorization server does not support obtaining an
            authorization code using this method.
            """
        )

        kwargs['error_description'] = error_description

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

    def unsupported_grant_type(self, **kwargs):
        kwargs['error_description'] = """
            The authorization grant type is not supported by the
            authorization server
            """
        return self.response_error('unsupported_grant_type', **kwargs)


class AuthorizationProvider(BaseProvider):
    should_force_ssl = True

    def verify_auth_request(self, *args, **kwargs):
        """ Verifies the authorization request and returns an auth code
        if requested

        You can either pass 1 parameter, url, or:

        required arguments:
            response_type
            client_id

        optional arguments:
            redirect_uri
            scope
            state
        """
        if len(args) == 1:
            url = args[0]
            qs = get_query_string(url)
            response_type = qs.pop('response_type', None)
            client_id = qs.pop('client_id', None)
            redirect_uri = qs.pop('redirect_uri', None)
            scope = qs.pop('scope', None)
            state = qs.pop('state', None)

        elif len(args) == 2:
            response_type = args[0]
            client_id = args[1]

            redirect_uri = kwargs.pop('redirect_uri', None)
            scope = kwargs.pop('scope', None)
            state = kwargs.pop('state', None)

        if not client_id: 
            return self.invalid_request(
                error_description = 'client_id is required'
                , redirect_uri = redirect_uri
                , state = state
            )

        if not response_type:
            return self.invalid_request(
                error_description = 'response_type is required'
                , redirect_uri = redirect_uri
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

        is_scope_valid = self.verify_scope(scope)

        if not is_scope_valid:
            return self.invalid_scope(
                redirect_uri = redirect_uri
                , state = state
            )

        is_authenticated = self.authenticate_user()

        if not is_authenticated:
            return self.access_denied(
                redirect_uri = redirect_uri
                , state = state
            )

        if response_type == 'code':
            # We are doing 4.1.1
            code = self.generate_authorization_code()

            # Save information to be used to validate later requests
            self.save_auth_code(
                client_id
                , code
                , scope
                , redirect_uri
            )

            new_qs = {'code': code}

            if state:
                new_qs['state'] = state

            return {
                'redirect_uri': clean_url(redirect_uri, new_qs,
                    should_force_ssl=self.should_force_ssl
                )
            }

        elif response_type == 'token':
            # We are doing 4.2.1
            token = self.generate_access_token()

            self.save_auth_token(token, None)

            # don't issue a refresh token in this mode

            #TODO: If scope is different than requested, return it

            return {'access_token': token }
        else:
            return self.unsupported_response_type(
                redirect_uri = redirect_uri
                , state = state
            )

    def redeem_code_for_token(self, *args, **kwargs):
        """ This takes an auth_code and turns it into an auth_token 
        It can either take a single dict or positional args:

        required arguments:
            grant_type
            code

        optional keyword arguments:
            redirect_uri
            client_id
        """
        if len(args) == 1:
            kwargs = args[0]

            grant_type = kwargs.pop('grant_type', None)
            code = kwargs.pop('code', None)
        elif len(args) == 2:
            grant_type = args[0]
            code = args[1]

        redirect_uri = kwargs.pop('redirect_uri', None)
        client_id = kwargs.pop('client_id', None)

        if redirect_uri == None:
            redirect_uri = self.get_redirect_uri(client_id)

        is_redirect_uri_valid = self.verify_redirect_uri(client_id,
                redirect_uri)

        if not is_redirect_uri_valid:
            return self.invalid_request()

        if grant_type != 'authorization_code':
            return self.unsupported_grant_type(
                redirect_uri = redirect_uri
            )

        is_valid_code = self.verify_auth_code(code)

        if not is_valid_code:
            return self.unauthorized_client(
                redirect_uri = redirect_uri
            )


        access_token = self.generate_access_token()
        refresh_token = self.generate_refresh_token()

        self.save_auth_token(access_token, refresh_token)

        return {
            'access_token': access_token
            , 'refresh_token': refresh_token
            , 'token_type': self.token_type
            , 'expires_in': self.token_expires_in
        }


    def authenticate_user(self):
        """
        This authenticates the user and makes sure they are currently logged
        in

        Should return True or False
        """
        raise NotImplementedError(
            """
                authenticate_user must be implemented by a child class
            """
        )

    def save_auth_code(self, client_id, code, scope, redirect_uri):
        """ This persists the authorization code to a datastore for
        checking against on the next request
        """
        raise NotImplementedError(
            """
                save_auth_code must be implemented by a child class
            """
        )

    def save_auth_token(self, access_token, refresh_token):
        """ This persists the authorization_token to a datastore for
        use with API calls
        """
        raise NotImplementedError(
            """
                save_auth_token must be implemented by a child class
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

    def verify_auth_code(self, code):
        """ This validates that the auth_code is legitimate and attached to an
        active user

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

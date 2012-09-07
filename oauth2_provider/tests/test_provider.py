from mock import Mock
import unittest

class TestBase(unittest.TestCase):
    def test_default_properties(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        assert provider.token_length == 32
        assert provider.token_type == 'Bearer'
        assert provider.token_expires_in == 60*10*10

    def test_authorization_code(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        auth_code = provider.generate_authorization_code()

        assert len(auth_code) == provider.token_length

    def test_access_token(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        token = provider.generate_access_token()

        assert len(token) == provider.token_length

    def test_refresh_token(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        token = provider.generate_refresh_token()

        assert len(token) == provider.token_length

    def test_response_error(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        results = provider.response_error('foo')

        assert results == {'error': 'foo'} 

        results = provider.response_error('bar', error_description='baz',
            error_uri='google.com', redirect_uri='cnn.com', state='foo'
        )

        assert results == {
            'error': 'bar'
            , 'error_description': 'baz'
            , 'error_uri': 'google.com'
            , 'redirect_uri': 'cnn.com'
            , 'state': 'foo'
        }

    def test_invalid_request(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        results = provider.invalid_request()

        assert results['error'] == 'invalid_request'

    def test_unsupported_response_type(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        results = provider.unsupported_response_type()

        assert results['error'] == 'unsupported_response_type'

    def test_access_denied(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        results = provider.access_denied()

        assert results['error'] == 'access_denied'

    def test_invalid_scope(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        results = provider.invalid_scope()

        assert results['error'] == 'invalid_scope'

    def test_unauthorized_client(self):
        from oauth2_provider.provider import BaseProvider

        provider = BaseProvider()

        results = provider.unauthorized_client()

        assert results['error'] == 'unauthorized_client'

class TestAuthorizationProvider(unittest.TestCase):
    def test_no_client_id(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()
        results = provider.verify_auth_request('Foo', None)

        assert results['error'] == 'invalid_request'

    def test_no_response_type(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()
        results = provider.verify_auth_request(None, 'Foo')

        assert results['error'] == 'invalid_request'

    def test_no_redirect_uri(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        get_redirect_uri = Mock()
        provider.verify_client_id = Mock()
        provider.verify_redirect_uri = Mock()
        provider.get_redirect_uri = get_redirect_uri

        provider.verify_auth_request('Foo', 'client_id_1')

        get_redirect_uri.assert_called_with('client_id_1')

    def test_client_id_invalid(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        verify_client_id = Mock(return_value = False)
        provider.verify_client_id = verify_client_id
        provider.verify_redirect_uri = Mock()

        results = provider.verify_auth_request('Foo', 'Foo1',
                redirect_uri='foo')

        assert results['error'] == 'unauthorized_client'


    def test_called_verify_client_id(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        verify_client_id = Mock()
        provider.verify_client_id = verify_client_id
        provider.verify_redirect_uri = Mock()

        provider.verify_auth_request('Foo', 'Foo1', redirect_uri='foo')

        verify_client_id.assert_called_with('Foo1')

    def test_redirect_uri_is_invalid(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        verify_client_id = Mock(return_value = True)
        verify_redirect_uri = Mock(return_value = False)
        provider.verify_client_id = verify_client_id
        provider.verify_redirect_uri = verify_redirect_uri

        results = provider.verify_auth_request('Foo', 'Foo1',
                redirect_uri='foo')

        assert results['error'] == 'invalid_request'

    def test_bad_response_type(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        verify_client_id = Mock(return_value = True)
        verify_redirect_uri = Mock(return_value = True)
        provider.verify_client_id = verify_client_id
        provider.verify_redirect_uri = verify_redirect_uri

        results = provider.verify_auth_request('BadCode', 'Foo1',
                redirect_uri='foo')

        assert results['error'] == 'unsupported_response_type'

    def test_scope_is_invalid(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        verify_client_id = Mock(return_value = True)
        verify_redirect_uri = Mock(return_value = True)
        verify_scope = Mock(return_value = False)

        provider.verify_client_id = verify_client_id
        provider.verify_redirect_uri = verify_redirect_uri
        provider.verify_scope = verify_scope

        results = provider.verify_auth_request('code', 'Foo1',
                redirect_uri='foo')

        assert results['error'] == 'invalid_scope'

    def test_called_save_data(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        verify_client_id = Mock(return_value = True)
        verify_redirect_uri = Mock(return_value = True)
        verify_scope = Mock(return_value = True)
        save_data = Mock()

        provider.verify_client_id = verify_client_id
        provider.verify_redirect_uri = verify_redirect_uri
        provider.verify_scope = verify_scope
        provider.save_data = save_data
        provider.generate_authorization_code = Mock(return_value='bar')

        redirect_uri = 'http://google.com'
        client_id = 'client_id'
        scope = 'foo,bar'
        state = 'omgz'

        results = provider.verify_auth_request('code', client_id,
                redirect_uri=redirect_uri, scope=scope, state=state)


        save_data.assert_called_with(client_id, 'bar', scope, redirect_uri)

        assert state in results['redirect_uri']

    def test_clean_url(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        verify_client_id = Mock(return_value = True)
        verify_redirect_uri = Mock(return_value = True)
        verify_scope = Mock(return_value = True)
        save_data = Mock()

        provider.verify_client_id = verify_client_id
        provider.verify_redirect_uri = verify_redirect_uri
        provider.verify_scope = verify_scope
        provider.save_data = save_data
        provider.generate_authorization_code = Mock(return_value='bar')

        redirect_uri = 'http://google.com?this=bad&so=is_this'
        client_id = 'client_id'
        scope = 'foo,bar'
        state = 'omgz'

        results = provider.verify_auth_request('code', client_id,
                redirect_uri=redirect_uri, scope=scope, state=state)


        save_data.assert_called_with(client_id, 'bar', scope, redirect_uri)

        assert state in results['redirect_uri']
        assert not 'this' in results['redirect_uri']
        assert not 'bad' in results['redirect_uri']
        assert not 'so' in results['redirect_uri']


    def test_save_data(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        with self.assertRaises(NotImplementedError):
            provider.save_data('foo', 'bar', 'baz', 'boom!')

    def test_verify_scope(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        with self.assertRaises(NotImplementedError):
            provider.verify_scope('foo', 'bar')

    def test_verify_redirect_uri(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        with self.assertRaises(NotImplementedError):
            provider.verify_redirect_uri('foo', 'bar')

    def test_get_redirect_uri(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        with self.assertRaises(NotImplementedError):
            provider.get_redirect_uri('foo')

    def test_verify_client_id(self):
        from oauth2_provider.provider import AuthorizationProvider
        provider = AuthorizationProvider()

        with self.assertRaises(NotImplementedError):
            provider.verify_client_id('foo')



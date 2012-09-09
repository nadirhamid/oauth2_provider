import hashlib
import random
import string
import urlparse
import urllib

def gen_api_key(length=24):
    """Generate an api key for the user to use"""
    m = hashlib.sha256()
    word = ''

    for i in xrange(length):
        word += random.choice(string.ascii_letters)

    m.update(word)

    return unicode(m.hexdigest()[:length])


def get_query_string(url):
    """
        Return query parameters as a dict from the specified URL.
    """
    return dict(urlparse.parse_qsl(urlparse.urlparse(url).query, True))

def force_ssl(url_str):
    url = urlparse.urlparse(url_str)

    return urlparse.urlunparse((
        "https",
        url.netloc,
        url.path,
        url.params,
        url.query,
        url.fragment
    ))


def clean_url(url, query={}, should_force_ssl=True):
    """ Gets the URL with new query string parameters """
    query = urllib.urlencode(query)
    result = urlparse.urlparse(url)._replace(query=query)

    url = urlparse.urlunparse(result)

    if should_force_ssl:
        url = force_ssl(url)

    return url

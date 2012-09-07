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

def clean_url(url, query={}):
    """ Gets the URL with new query string parameters """
    query = urllib.urlencode(query)
    result = urlparse.urlparse(url)._replace(query=query)

    return urlparse.urlunparse(result)

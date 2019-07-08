"""Tests for plugin.py.
MSAL and CKAN handle their own testing. This only tests custom pieces
that are unique to this plugin.
"""
import ckanext.msal.plugin as plugin

import ckanext.adal.adal_config as adal_config
import ckan.model as model
import ckan.plugins as plugins
from nose.tools import assert_equals, ok_, assert_raises
from ckan.tests import factories, helpers


class TestMsal(object):
    def setup(self):
        self.app = helpers._get_test_app()

        if not plugins.plugin_loaded(u'msal'):
            plugins.load(u'msal')
            plugin = plugins.get_plugin(u'msal')
            self.app.flask_app.register_extension_blueprint(
                plugin.get_blueprint())

    def teardown(self):
        '''Nose runs this method after each test method in our test class.'''
        # Rebuild CKAN's database after each test method, so that each test
        # method runs with a clean slate.
        model.repo.rebuild_db()

    def test_validate_email_domains(self):
        '''Only those email domains from config should validate.
        '''
        email = 'Luke.Skywalker@' + adal_config.EMAIL_DOMAINS[0]
        assert_equals(plugin._validate_email_domains(email), True)
        assert_equals(plugin._validate_email_domains('Darth.Vader@gmail.com'),
                      False)

    def test_validate_user_exists_in_ckan(self):
        '''Only users registerd in CKAN should validate.
        '''
        user = factories.User()

        valid_user = plugin._validate_user_exists_in_ckan(
            user['email'],
            user['name'])
        is_not_valid_user = plugin._validate_user_exists_in_ckan(
            'darth.vader@workplace.com',
            'darth_vader')
        assert_equals(valid_user, True)
        assert_equals(is_not_valid_user, False)

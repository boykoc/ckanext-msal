# CKAN
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
import ckan.model as model
from ckan.common import config, request, g
from flask import Blueprint

# MSAL
import msal

# Plugin
import msal_config as msal_config

log = logging.getLogger(__name__)
application = msal.ConfidentialClientApplication(
        msal_config.CLIENT_ID,
        authority=msal_config.AUTHORITY,
        client_credential=msal_config.CLIENT_SECRET
    )


def _validate_email_domains(user):
    '''Validate user's email domain is allowed.
    Potential for guest user to be added to Azure AD that
    we don't want to be accepted in CKAN, even if added there.
    '''
    try:
        domain = user.split('@')[1].lower()
        if not domain in msal_config.EMAIL_DOMAINS:
            raise Exception(user)
    except Exception as e:
        log.error('Exception raised. Improper email domain. {}'
                  .format(repr(e)))
        return False
    return True


def _validate_user_exists_in_ckan(user, user_name):
    '''Validate the user is registered and active in CKAN.
    Return boolean.
    Checks if user exists based on username.
    Checks if user is active.
    Chekcs if user email is a complete match (just username may provide false
    match to differnet domain).
    Check state, state: deleted can still login but gets a blank page because
    CKAN is handling authorization later as well.
    '''
    try:
        user_obj = model.User.get(user_name)
        if (user_obj and
                user_obj.state == 'active' and
                user_obj.email.lower() == user.lower()):
            return True
        else:
            raise Exception(user_name)
    except (toolkit.ObjectNotFound, Exception) as e:
        log.error('Exception raised. Invalid user. {}'
                  .format(repr(e)))
        return False


def msal_login():
    '''Make call to authorization_url to authenticate user and get
    authorization code.
    '''
    authorization_url = application.get_authorization_request_url(
            msal_config.SCOPE,
            redirect_uri=msal_config.REDIRECT_URI
        )

    resp = toolkit.h.redirect_to(authorization_url)

    return resp


def get_a_token():
    '''Handle Azure AD callback.
    Get authorization code from Azure AD response. Use code to get
    token.
    Returns response to dashboard if logged in or aborts with 403.
    '''
    try:
        code = request.args['code']

        result = application.acquire_token_by_authorization_code(code,
                scopes=msal_config.SCOPE,
                redirect_uri=msal_config.REDIRECT_URI
            )

        user = result.get("id_token_claims", {}).get("preferred_username") # email
        user_name = user.lower().replace('.', '_').split('@')[0].strip() # ckan'd username

        # Validate user info.
        if not _validate_email_domains(user):
            raise Exception(user)
        if not _validate_user_exists_in_ckan(user, user_name):
            raise Exception(user)

        # Note: If developing locally make sure the site_url is set to http://localhost
        #       and not 127.0.0.1 otherwise it will log the user out.
        resp = toolkit.h.redirect_to('/dashboard')

        # Set the repoze.who cookie to match a given user_id
        if u'repoze.who.plugins' in request.environ:
            rememberer = request.environ[u'repoze.who.plugins'][u'friendlyform']
            identity = {u'repoze.who.userid': user_name}
            resp.headers.extend(rememberer.remember(request.environ, identity))
    except Exception as e:
        log.error('Exception raised. Unable to authenticate user. {}'
                  .format(repr(e)))
        toolkit.abort(403, 'Not authorized.')

    return resp

class MsalPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'msal')


    # IBlueprint

    def get_blueprint(self):
        blueprint = Blueprint(self.name, self.__module__)
        rules = [
            ('/msal/login', 'msal_login', msal_login),
            ('/getAToken', 'get_a_token', get_a_token)
        ]

        for rule in rules:
            blueprint.add_url_rule(*rule)

        return blueprint


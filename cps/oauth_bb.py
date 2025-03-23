# -*- coding: utf-8 -*-

#  This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
#    Copyright (C) 2018-2019 OzzieIsaacs, cervinko, jkrehm, bodybybuddha, ok11,
#                            andy29485, idalin, Kyosfonica, wuqi, Kennyl, lemmsh,
#                            falgh1, grunjol, csitko, ytils, xybydy, trasba, vrabe,
#                            ruben-herold, marblepebble, JackED42, SiphonSquirrel,
#                            apetresc, nanu-c, mutschler
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>

import json
from functools import wraps

from flask import session, request, make_response, abort
from flask import Blueprint, flash, redirect, url_for
from flask_babel import gettext as _
from flask_dance.consumer import oauth_authorized, oauth_error, OAuth2ConsumerBlueprint
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2 import TokenExpiredError, InvalidGrantError
from .cw_login import login_user, current_user
from sqlalchemy.orm.exc import NoResultFound
from os import getenv
from .usermanagement import user_login_required

from . import constants, logger, config, app, ub

try:
    from .oauth import OAuthBackend, backend_resultcode
except NameError:
    pass


oauth_check = {}
oauthblueprints = []
oauth = Blueprint('oauth', __name__)
log = logger.create()


def oauth_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if config.config_login_type == constants.LOGIN_OAUTH:
            return f(*args, **kwargs)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            data = {'status': 'error', 'message': 'Not Found'}
            response = make_response(json.dumps(data, ensure_ascii=False))
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response, 404
        abort(404)

    return inner


def register_oauth_blueprint(cid, name, display_name):
    oauth_check[cid] = dict(name=name, display_name=display_name)


def register_user_with_oauth(user=None):
    all_oauth = {}
    for oauth_key in oauth_check.keys():
        if str(oauth_key) + '_oauth_user_id' in session and session[str(oauth_key) + '_oauth_user_id'] != '':
            all_oauth[oauth_key] = oauth_check[oauth_key]
    if len(all_oauth.keys()) == 0:
        return
    if user is None:
        flash(_("Register with %(provider)s", provider=", ".join(list(all_oauth.values()))), category="success")
    else:
        for oauth_key in all_oauth.keys():
            # Find this OAuth token in the database, or create it
            query = ub.session.query(ub.OAuth).filter_by(
                provider=oauth_key,
                provider_user_id=session[str(oauth_key) + "_oauth_user_id"],
            )
            try:
                oauth_key = query.one()
                oauth_key.user_id = user.id
            except NoResultFound:
                # no found, return error
                return
            ub.session_commit("User {} with OAuth for provider {} registered".format(user.name, oauth_key))


def logout_oauth_user():
    for oauth_key in oauth_check.keys():
        if str(oauth_key) + '_oauth_user_id' in session:
            session.pop(str(oauth_key) + '_oauth_user_id')


def oauth_update_token(provider_id, token, provider_user_id):
    session[provider_id + "_oauth_user_id"] = provider_user_id
    session[provider_id + "_oauth_token"] = token

    # Find this OAuth token in the database, or create it
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider_id,
        provider_user_id=provider_user_id,
    )
    try:
        oauth_entry = query.one()
        # update token
        oauth_entry.token = token
    except NoResultFound:
        oauth_entry = ub.OAuth(
            provider=provider_id,
            provider_user_id=provider_user_id,
            token=token,
        )
    ub.session.add(oauth_entry)
    ub.session_commit()

    # Disable Flask-Dance's default behavior for saving the OAuth token
    # Value differrs depending on flask-dance version
    return backend_resultcode


def bind_oauth_or_register(provider_id, provider_user_id, redirect_url, provider_name):
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider_id,
        provider_user_id=provider_user_id,
    )
    try:
        oauth_entry = query.first()
        # already bind with user, just login
        if oauth_entry.user:
            login_user(oauth_entry.user)
            log.debug("You are now logged in as: '%s'", oauth_entry.user.name)
            flash(_("Success! You are now logged in as: %(nickname)s", nickname=oauth_entry.user.name),
                  category="success")
            return redirect(url_for('web.index'))
        else:
            # bind to current user
            if current_user and current_user.is_authenticated:
                oauth_entry.user = current_user
                try:
                    ub.session.add(oauth_entry)
                    ub.session.commit()
                    flash(_("Link to %(oauth)s Succeeded", oauth=provider_name), category="success")
                    log.info("Link to {} Succeeded".format(provider_name))
                    return redirect(url_for('web.profile'))
                except Exception as ex:
                    log.error_or_exception(ex)
                    ub.session.rollback()
            else:
                flash(_("Login failed, No User Linked With OAuth Account"), category="error")
            log.info('Login failed, No User Linked With OAuth Account')
            return redirect(url_for('web.login'))
            # return redirect(url_for('web.login'))
            # if config.config_public_reg:
            #   return redirect(url_for('web.register'))
            # else:
            #    flash(_("Public registration is not enabled"), category="error")
            #    return redirect(url_for(redirect_url))
    except (NoResultFound, AttributeError):
        return redirect(url_for(redirect_url))


def get_oauth_status():
    status = []
    query = ub.session.query(ub.OAuth).filter_by(
        user_id=current_user.id,
    )
    try:
        oauths = query.all()
        for oauth_entry in oauths:
            status.append(int(oauth_entry.provider))
        return status
    except NoResultFound:
        return None


def unlink_oauth(provider):
    if request.host_url + 'me' != request.referrer:
        pass
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider,
        user_id=current_user.id,
    )
    try:
        oauth_entry = query.one()
        if current_user and current_user.is_authenticated:
            oauth_entry.user = current_user
            try:
                ub.session.delete(oauth_entry)
                ub.session.commit()
                logout_oauth_user()
                flash(_("Unlink to %(oauth)s Succeeded", oauth=oauth_check[provider]['display_name']), category="success")
                log.info("Unlink to {} Succeeded".format(oauth_check[provider]['display_name']))
            except Exception as ex:
                log.error_or_exception(ex)
                ub.session.rollback()
                flash(_("Unlink to %(oauth)s Failed", oauth=oauth_check[provider]['display_name']), category="error")
    except NoResultFound:
        log.warning("oauth %s for user %d not found", provider, current_user.id)
        flash(_("Not Linked to %(oauth)s", oauth=provider), category="error")
    return redirect(url_for('web.profile'))


def generate_oauth_blueprints():
    if not ub.session.query(ub.OAuthProvider).count():
        for provider in ("github", "google", "custom"):
            oauthProvider = ub.OAuthProvider()
            oauthProvider.provider_name = provider
            oauthProvider.active = False
            ub.session.add(oauthProvider)
            ub.session_commit("{} Blueprint Created".format(provider))

    oauth_ids = ub.session.query(ub.OAuthProvider).all()
    ele1 = dict(provider_name='github', display_name='github',
                id=oauth_ids[0].id,
                active=oauth_ids[0].active,
                oauth_client_id=oauth_ids[0].oauth_client_id,
                scope=None,
                oauth_client_secret=oauth_ids[0].oauth_client_secret,
                obtain_link='https://github.com/settings/developers')
    ele2 = dict(provider_name='google', display_name='google',
                id=oauth_ids[1].id,
                active=oauth_ids[1].active,
                scope=["https://www.googleapis.com/auth/userinfo.email"],
                oauth_client_id=oauth_ids[1].oauth_client_id,
                oauth_client_secret=oauth_ids[1].oauth_client_secret,
                obtain_link='https://console.developers.google.com/apis/credentials')
    oauthblueprints.append(ele1)
    oauthblueprints.append(ele2)

    if (
            getenv('CALIBREWEB_CUSTOM_OAUTH') == 'true' and
            getenv('CALIBREWEB_CUSTOM_OAUTH_SCOPE') and
            getenv('CALIBREWEB_CUSTOM_OAUTH_CLIENT_ID') and
            getenv('CALIBREWEB_CUSTOM_OAUTH_SECRET') and
            getenv('CALIBREWEB_CUSTOM_OAUTH_BASEURL') and
            getenv('CALIBREWEB_CUSTOM_OAUTH_TOKENURL') and
            getenv('CALIBREWEB_CUSTOM_OAUTH_AUTHURL') and
            getenv('CALIBREWEB_CUSTOM_USERINFO_PATH')
        ):
        ele3 = dict(provider_name="custom",
                    name="custom",
                    display_name=getenv('CALIBREWEB_CUSTOM_OAUTH_NAME', 'custom'),
                    id=oauth_ids[2].id,
                    active=True,
                    scope=getenv('CALIBREWEB_CUSTOM_OAUTH_SCOPE').split(','),
                    oauth_client_id=getenv('CALIBREWEB_CUSTOM_OAUTH_CLIENT_ID'),
                    oauth_client_secret=getenv('CALIBREWEB_CUSTOM_OAUTH_SECRET'),
                    oauth_base_url=getenv('CALIBREWEB_CUSTOM_OAUTH_BASEURL'),
                    oauth_token_url=getenv('CALIBREWEB_CUSTOM_OAUTH_TOKENURL'),
                    oauth_authorization_url=getenv('CALIBREWEB_CUSTOM_OAUTH_AUTHURL')
                )
        oauthblueprints.append(ele3)
    for element in oauthblueprints:
        if element['provider_name'] == 'custom':
            blueprint = OAuth2ConsumerBlueprint(
                element['name'], __name__,
                client_id=element['oauth_client_id'],
                client_secret=element['oauth_client_secret'],
                base_url=element['oauth_base_url'],
                scope=element['scope'],
                token_url=element['oauth_token_url'],
                authorization_url=element['oauth_authorization_url'],
                redirect_to="oauth."+element['provider_name']+"_login",
            )
        else:
            if element['provider_name'] == 'github':
                blueprint_func = make_github_blueprint
            else:
                blueprint_func = make_google_blueprint
            blueprint = blueprint_func(
                client_id=element['oauth_client_id'],
                client_secret=element['oauth_client_secret'],
                redirect_to="oauth."+element['provider_name']+"_login",
                scope=element['scope']
            )

        element['blueprint'] = blueprint
        element['blueprint'].backend = OAuthBackend(ub.OAuth, ub.session, str(element['id']),
                                                    user=current_user, user_required=True)
        app.register_blueprint(blueprint, url_prefix="/login")
        if element['active']:
            register_oauth_blueprint(element['id'], element['provider_name'], element['display_name'])
    return oauthblueprints


if ub.oauth_support:
    oauthblueprints = generate_oauth_blueprints()

    @oauth_authorized.connect_via(oauthblueprints[0]['blueprint'])
    def github_logged_in(blueprint, token):
        if not token:
            flash(_("Failed to log in with GitHub."), category="error")
            log.error("Failed to log in with GitHub")
            return False

        resp = blueprint.session.get("/user")
        if not resp.ok:
            flash(_("Failed to fetch user info from GitHub."), category="error")
            log.error("Failed to fetch user info from GitHub")
            return False

        github_info = resp.json()
        github_user_id = str(github_info["id"])
        return oauth_update_token(str(oauthblueprints[0]['id']), token, github_user_id)


    @oauth_authorized.connect_via(oauthblueprints[1]['blueprint'])
    def google_logged_in(blueprint, token):
        if not token:
            flash(_("Failed to log in with Google."), category="error")
            log.error("Failed to log in with Google")
            return False

        resp = blueprint.session.get("/oauth2/v2/userinfo")
        if not resp.ok:
            flash(_("Failed to fetch user info from Google."), category="error")
            log.error("Failed to fetch user info from Google")
            return False

        google_info = resp.json()
        google_user_id = str(google_info["id"])
        return oauth_update_token(str(oauthblueprints[1]['id']), token, google_user_id)

    if len(oauthblueprints) > 2:
        @oauth_authorized.connect_via(oauthblueprints[2]['blueprint'])
        def custom_logged_in(blueprint, token):
            if not token:
                flash(_("Failed to log in with Custom."), category="error")
                log.error("Failed to log in with Custom")
                return False

            resp = blueprint.session.get(getenv('CALIBREWEB_CUSTOM_USERINFO_PATH'))
            if not resp.ok:
                flash(_("Failed to fetch user info from Custom."), category="error")
                log.error("Failed to fetch user info from Custom")
                return False

            user_info = resp.json()
            provider_id = str(oauthblueprints[2]['id'])
            provider_user_id = str(user_info[getenv('CALIBREWEB_CUSTOM_USER_ID', 'sub')])
            response = oauth_update_token(provider_id, token, provider_user_id)

            if getenv('CALIBREWEB_CUSTOM_USER_AUTOREGISTER') == 'true':
                # fetch session
                query = ub.session.query(ub.OAuth).filter_by(
                    provider=provider_id,
                    provider_user_id=provider_user_id,
                )
                try:
                    oauth_entry = query.one()
                    if not oauth_entry.user_id:
                        try:
                            query = ub.session.query(ub.User).filter_by(
                                email=str(user_info[getenv('CALIBREWEB_CUSTOM_USER_EMAIL', 'email')]),
                            )
                            new_user = query.one()
                        except:
                            new_user = ub.User(
                                name=str(user_info[getenv('CALIBREWEB_CUSTOM_USER_NAME', 'name')]),
                                email=str(user_info[getenv('CALIBREWEB_CUSTOM_USER_EMAIL', 'email')]),
                                role=constants.ROLE_USER | constants.ROLE_DOWNLOAD | constants.ROLE_UPLOAD | constants.ROLE_EDIT | constants.ROLE_EDIT_SHELFS | constants.ROLE_VIEWER,
                                password='*'
                            )
                        groups_name = getenv('CALIBREWEB_CUSTOM_USER_GROUPS', 'groups')
                        admin_group_name = getenv('CALIBREWEB_CUSTOM_USER_ADMINS_GROUP', 'admins')
                        if groups_name in user_info and admin_group_name in user_info[groups_name]:
                            new_user.role |= constants.ROLE_ADMIN
                        ub.session.add(new_user)
                        ub.session_commit()
                        ub.session.refresh(new_user)
                        oauth_entry.user_id = new_user.id
                        ub.session.add(oauth_entry)
                        ub.session_commit()
                except NoResultFound:
                    pass

            return response


    # notify on OAuth provider error
    @oauth_error.connect_via(oauthblueprints[0]['blueprint'])
    def github_error(blueprint, error, error_description=None, error_uri=None):
        msg = (
            "OAuth error from {name}! "
            "error={error} description={description} uri={uri}"
        ).format(
            name=blueprint.name,
            error=error,
            description=error_description,
            uri=error_uri,
        )  # ToDo: Translate
        flash(msg, category="error")

    @oauth_error.connect_via(oauthblueprints[1]['blueprint'])
    def google_error(blueprint, error, error_description=None, error_uri=None):
        msg = (
            "OAuth error from {name}! "
            "error={error} description={description} uri={uri}"
        ).format(
            name=blueprint.name,
            error=error,
            description=error_description,
            uri=error_uri,
        )  # ToDo: Translate
        flash(msg, category="error")

    if len(oauthblueprints) > 2:
        @oauth_error.connect_via(oauthblueprints[2]['blueprint'])
        def custom_error(blueprint, error, error_description=None, error_uri=None):
            msg = (
                "OAuth error from {name}! "
                "error={error} description={description} uri={uri}"
            ).format(
                name=blueprint.name,
                error=error,
                description=error_description,
                uri=error_uri,
            )  # ToDo: Translate
            flash(msg, category="error")

@oauth.route('/link/github')
@oauth_required
def github_login():
    if not github.authorized:
        return redirect(url_for('github.login'))
    try:
        account_info = github.get('/user')
        if account_info.ok:
            account_info_json = account_info.json()
            return bind_oauth_or_register(oauthblueprints[0]['id'], account_info_json['id'], 'github.login', 'github')
        flash(_("GitHub Oauth error, please retry later."), category="error")
        log.error("GitHub Oauth error, please retry later")
    except (InvalidGrantError, TokenExpiredError) as e:
        flash(_("GitHub Oauth error: {}").format(e), category="error")
        log.error(e)
    return redirect(url_for('web.login'))


@oauth.route('/unlink/github', methods=["GET"])
@user_login_required
def github_login_unlink():
    return unlink_oauth(oauthblueprints[0]['id'])


@oauth.route('/link/google')
@oauth_required
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    try:
        resp = google.get("/oauth2/v2/userinfo")
        if resp.ok:
            account_info_json = resp.json()
            return bind_oauth_or_register(oauthblueprints[1]['id'], account_info_json['id'], 'google.login', 'google')
        flash(_("Google Oauth error, please retry later."), category="error")
        log.error("Google Oauth error, please retry later")
    except (InvalidGrantError, TokenExpiredError) as e:
        flash(_("Google Oauth error: {}").format(e), category="error")
        log.error(e)
    return redirect(url_for('web.login'))


@oauth.route('/unlink/google', methods=["GET"])
@user_login_required
def google_login_unlink():
    return unlink_oauth(oauthblueprints[1]['id'])

if len(oauthblueprints) > 2:
    @oauth.route('/link/custom')
    @oauth_required
    def custom_login():
        blueprint = oauthblueprints[2]['blueprint']
        if not blueprint.session.authorized:
            return redirect(url_for('custom.login'))
        try:
            resp = blueprint.session.get(getenv('CALIBREWEB_CUSTOM_USERINFO_PATH'))
            if resp.ok:
                account_info_json = resp.json()
                return bind_oauth_or_register(oauthblueprints[2]['id'], account_info_json[getenv('CALIBREWEB_CUSTOM_USER_ID', 'sub')], 'custom.login', 'custom')
            flash(_("Custom Oauth error, please retry later."), category="error")
            log.error("Custom Oauth error, please retry later")
        except (InvalidGrantError, TokenExpiredError) as e:
            flash(_("Custom Oauth error: {}").format(e), category="error")
            log.error(e)
        return redirect(url_for('web.login'))


    @oauth.route('/unlink/custom', methods=["GET"])
    @user_login_required
    def custom_login_unlink():
        return unlink_oauth(oauthblueprints[2]['id'])

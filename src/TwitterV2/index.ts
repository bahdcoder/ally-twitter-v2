/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| This is a dummy implementation of the Oauth driver. Make sure you
|
| - Got through every line of code
| - Read every comment
|
*/

// import b from 'base64-arraybuffer'
// import Got from 'got'
import crypto from 'crypto'
import { Buffer } from 'buffer'
import base64url from 'base64url'
import type {
  AllyUserContract,
  ApiRequestContract,
  LiteralStringUnion,
} from '@ioc:Adonis/Addons/Ally'
import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { Oauth2Driver, ApiRequest, RedirectRequest } from '@adonisjs/ally/build/standalone'

/**
 * Define the access token object properties in this type. It
 * must have "token" and "type" and you are free to add
 * more properties.
 *
 * ------------------------------------------------
 * Change "TwitterV2" to something more relevant
 * ------------------------------------------------
 */
export type TwitterV2AccessToken = {
  token: string
  type: 'bearer'
  expiresIn: number
  refreshToken: string
  scope: string
}

/**
 * Define a union of scopes your driver accepts. Here's an example of same
 * https://github.com/adonisjs/ally/blob/develop/adonis-typings/ally.ts#L236-L268
 *
 * ------------------------------------------------
 * Change "TwitterV2" to something more relevant
 * ------------------------------------------------
 */
export type TwitterV2Scopes =
  | 'tweet.read'
  | 'tweet.write'
  | 'tweet.moderate.write'
  | 'users.read'
  | 'follows.read'
  | 'follows.write'
  | 'offline.access'
  | 'space.read'
  | 'mute.read'
  | 'mute.write'
  | 'like.read'
  | 'like.write'
  | 'list.read'
  | 'list.write'
  | 'block.read'
  | 'block.write'

/**
 * Define the configuration options accepted by your driver. It must have the following
 * properties and you are free add more.
 *
 * ------------------------------------------------
 * Change "TwitterV2" to something more relevant
 * ------------------------------------------------
 */
export type TwitterV2Config = {
  driver: 'twitter_v2'
  clientId: string
  clientSecret: string
  callbackUrl: string
  authorizeUrl?: string
  accessTokenUrl?: string
  userInfoUrl?: string
  scopes?: LiteralStringUnion<TwitterV2Scopes>[]
}

/**
 * Driver implementation. It is mostly configuration driven except the user calls
 *
 * ------------------------------------------------
 * Change "TwitterV2" to something more relevant
 * ------------------------------------------------
 */
export class TwitterV2 extends Oauth2Driver<TwitterV2AccessToken, TwitterV2Scopes> {
  /**
   * The URL for the redirect request. The user will be redirected on this page
   * to authorize the request.
   *
   * Do not define query strings in this URL.
   */
  protected authorizeUrl = 'https://twitter.com/i/oauth2/authorize'

  /**
   * The URL to hit to exchange the authorization code for the access token
   *
   * Do not define query strings in this URL.
   */
  protected accessTokenUrl = 'https://api.twitter.com/2/oauth2/token'

  /**
   * The URL to hit to get the user details
   *
   * Do not define query strings in this URL.
   */
  protected userInfoUrl = 'https://api.twitter.com/2/users/me'

  /**
   * The param name for the authorization code. Read the documentation of your oauth
   * provider and update the param name to match the query string field name in
   * which the oauth provider sends the authorization_code post redirect.
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error. Read the documentation of your oauth provider and update
   * the param name to match the query string field name in which the oauth provider sends
   * the error post redirect
   */
  protected errorParamName = 'error'

  /**
   * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
   * approach is to prefix the oauth provider name to `oauth_state` value. For example:
   * For example: "facebook_oauth_state"
   */
  protected stateCookieName = 'twitter_v2_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   * Read the documentation of your oauth provider and update the param
   * name to match the query string used by the provider for exchanging
   * the state.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'scope'

  /**
   * Save the code verifier from the encrypted cookies.
   */
  protected codeVerifier = ''

  /**
   * The name of the cookie used to store the code verifier
   * on the user's browser.
   */
  protected codeVerifierName = 'code_verifier'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ' '

  constructor(ctx: HttpContextContract, public config: TwitterV2Config) {
    super(ctx, config)

    /**
     * Extremely important to call the following method to clear the
     * state set by the redirect request.
     *
     * DO NOT REMOVE THE FOLLOWING LINE
     */
    this.loadState()
    this.loadCodeVerifierState()
  }

  /**
   * Load the code verifier from the encrypted cookies. Make sure
   * to clear it from the response immediately after.
   */
  protected loadCodeVerifierState() {
    if (this.isStateless) {
      return
    }

    this.codeVerifier = this.ctx.request.encryptedCookie(this.codeVerifierName)
    this.ctx.response.clearCookie(this.codeVerifierName)
  }

  /**
   * Store the verifier on an http-only cookie.
   *
   * @returns void
   */
  protected persistVerifierState() {
    if (this.isStateless) {
      return
    }

    this.ctx.response.encryptedCookie(this.codeVerifierName, this.codeVerifier, {
      sameSite: false,
      httpOnly: true,
    })
  }

  public getThings() {
    return {
      codeVerifier: this.codeVerifier,
      state: this.stateCookieValue,
    }
  }

  /**
   * Optionally configure the authorization redirect request. The actual request
   * is made by the base implementation of "Oauth2" driver and this is a
   * hook to pre-configure the request.
   */
  protected configureRedirectRequest(request: RedirectRequest<TwitterV2Scopes>) {
    this.generateCodeVerifier()
    this.generateCodeChallenge()

    /**
     * Define user defined scopes or the default one's
     */
    request.scopes(this.config.scopes || ['users.read', 'tweet.read'])

    request.param('response_type', 'code')
    request.param('code_challenge', this.codeVerifier)
    request.param('code_challenge_method', 'plain')

    this.persistVerifierState()
  }

  /**
   * Optionally configure the access token request. The actual request is made by
   * the base implementation of "Oauth2" driver and this is a hook to pre-configure
   * the request
   */
  protected configureAccessTokenRequest(request: ApiRequest) {
    /**
     * Send state to twitter when request is not stateles
     */
    if (!this.isStateless) {
      request.field('state', this.stateCookieValue)
    }

    request.field('code', this.getCode())

    request.header('Content-Type', 'application/x-www-form-urlencoded')

    request.header('Authorization', `Basic ${this.generateBasicAuthenticationCredentials()}`)

    request.field('code_verifier', this.codeVerifier)
  }

  /**
   * Returns the HTTP request with the authorization header set
   */
  protected getAuthenticatedRequest(url: string, token: string) {
    const request = this.httpClient(url)

    request.header('Authorization', `Bearer ${token}`)
    request.header('Accept', 'application/json')
    request.parseAs('json')

    return request
  }

  /**
   * Fetches the user info from the Twitter v2 API
   */
  protected async getUserInfo(token: string, callback?: (request: ApiRequestContract) => void) {
    const request = this.getAuthenticatedRequest(this.config.userInfoUrl || this.userInfoUrl, token)

    if (typeof callback === 'function') {
      callback(request)
    }

    request.param('user.fields', 'id,username,profile_image_url,name,verified')

    const { data } = await request.get()

    return {
      id: data.id,
      nickName: data.username,
      name: data.name,
      email: data.email,
      avatarUrl: data.profile_image_url,
      emailVerificationState: data.verified
        ? 'verified'
        : ('unverified' as AllyUserContract<TwitterV2AccessToken>['emailVerificationState']),
      original: data,
    }
  }

  /**
   * Update the implementation to tell if the error received during redirect
   * means "ACCESS DENIED".
   */
  public accessDenied() {
    return this.ctx.request.input('error') === 'access_denied'
  }

  /**
   * Get the user details by query the provider API. This method must return
   * the access token and the user details both. Checkout the google
   * implementation for same.
   *
   * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
   */
  public async user(
    callback?: (request: ApiRequest) => void
  ): Promise<AllyUserContract<TwitterV2AccessToken>> {
    const accessToken = await this.accessToken()

    const user = await this.getUserInfo(accessToken.token, callback)

    /**
     * Write your implementation details here
     */
    return {
      token: accessToken,
      ...user,
    }
  }

  public async userFromToken(
    accessToken: string,
    callback?: (request: ApiRequest) => void
  ): Promise<AllyUserContract<{ token: string; type: 'bearer' }>> {
    const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl)

    /**
     * Allow end user to configure the request. This should be called after your custom
     * configuration, so that the user can override them (if required)
     */
    if (typeof callback === 'function') {
      callback(request)
    }

    const user = await this.getUserInfo(accessToken, callback)

    /**
     * Write your implementation details here
     */
    return {
      token: { token: accessToken, type: 'bearer' },
      ...user,
    }
  }

  /**
   * Generate a random code verifier to be used
   *
   * @returns string
   */
  protected generateCodeVerifier() {
    this.codeVerifier = base64url(crypto.pseudoRandomBytes(48))
      .replace(/\+/g, '')
      .replace(/\//g, '')
      .replace(/=/g, '')
      .replace(/-/g, '')
      .replace(/_/g, '')

    return this.codeVerifier
  }

  /**
   * The code challenge to be sent to authorization server.
   *
   * @returns string
   */
  protected generateCodeChallenge() {
    return this.codeVerifier
  }

  protected generateBasicAuthenticationCredentials() {
    return Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')
  }
}

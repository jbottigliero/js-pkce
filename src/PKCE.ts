import IAuthResponse from './IAuthResponse';
import IConfig from './IConfig';
import IObject from './IObject';
import ITokenResponse from './ITokenResponse';
import ICorsOptions from './ICorsOptions';

function getCrypto() {
  return globalThis.crypto;
}

async function sha256(input: string) {
  const hashBuffer = await getCrypto().subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(hashBuffer))
    .map((item) => item.toString(16).padStart(2, '0'))
    .join('');
}

export const createRandomString = () => {
  const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~.';
  let random = '';
  const randomValues = Array.from(getCrypto().getRandomValues(new Uint8Array(43)));
  randomValues.forEach((v) => (random += charset[v % charset.length]));
  return random;
};

export const encode = (value: string) => btoa(value);
export const decode = (value: string) => atob(value);

export default class PKCE {
  private config: IConfig;
  private state: string = '';
  private codeVerifier: string = '';
  private corsRequestOptions: ICorsOptions = {};

  /**
   * Initialize the instance with configuration
   * @param {IConfig} config
   */
  constructor(config: IConfig) {
    this.config = config;
  }

  /**
   * Allow the user to enable cross domain cors requests
   * @param  enable turn the cross domain request options on.
   * @return ICorsOptions
   */
  public enableCorsCredentials(enable: boolean): ICorsOptions {
    this.corsRequestOptions = enable
      ? {
          credentials: 'include',
          mode: 'cors',
        }
      : {};
    return this.corsRequestOptions;
  }

  /**
   * Generate the authorize url
   * @param  {object} additionalParams include additional parameters in the query
   */
  public async authorizeUrl(additionalParams: IObject = {}) {
    const codeChallenge = await this.pkceChallengeFromVerifier();

    const queryString = new URLSearchParams(
      Object.assign(
        {
          response_type: 'code',
          client_id: this.config.client_id,
          state: this.getState(additionalParams.state || null),
          scope: this.config.requested_scopes,
          redirect_uri: this.config.redirect_uri,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        },
        additionalParams,
      ),
    ).toString();

    return `${this.config.authorization_endpoint}?${queryString}`;
  }

  /**
   * Given the return url, get a token from the oauth server
   * @param  url current urlwith params from server
   * @param  {object} additionalParams include additional parameters in the request body
   * @return {Promise<ITokenResponse>}
   */
  public exchangeForAccessToken(url: string, additionalParams: IObject = {}): Promise<ITokenResponse> {
    return this.parseAuthResponseUrl(url).then((q) => {
      return fetch(this.config.token_endpoint, {
        method: 'POST',
        body: new URLSearchParams(
          Object.assign(
            {
              grant_type: 'authorization_code',
              code: q.code,
              client_id: this.config.client_id,
              redirect_uri: this.config.redirect_uri,
              code_verifier: this.getCodeVerifier(),
            },
            additionalParams,
          ),
        ),
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        },
        ...this.corsRequestOptions,
      }).then((response) => response.json());
    });
  }

  /**
   * Given a refresh token, return a new token from the oauth server
   * @param  refreshTokens current refresh token from server
   * @return {Promise<ITokenResponse>}
   */
  public refreshAccessToken(refreshToken: string): Promise<ITokenResponse> {
    return fetch(this.config.token_endpoint, {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.client_id,
        refresh_token: refreshToken,
      }),
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      },
    }).then((response) => response.json());
  }

  /**
   * Get the current codeVerifier or generate a new one
   * @return {string}
   */
  private getCodeVerifier(): string {
    if (this.codeVerifier === '') {
      this.codeVerifier = this.randomStringFromStorage('pkce_code_verifier');
    }

    return this.codeVerifier;
  }

  /**
   * Get the current state or generate a new one
   * @return {string}
   */
  private getState(explicit: string = null): string {
    const stateKey = 'pkce_state';

    if (explicit !== null) {
      this.getStore().setItem(stateKey, explicit);
    }

    if (this.state === '') {
      this.state = this.randomStringFromStorage(stateKey);
    }

    return this.state;
  }

  /**
   * Get the query params as json from a auth response url
   * @param  {string} url a url expected to have AuthResponse params
   * @return {Promise<IAuthResponse>}
   */
  private parseAuthResponseUrl(url: string): Promise<IAuthResponse> {
    const params = new URL(url).searchParams;

    return this.validateAuthResponse({
      error: params.get('error'),
      query: params.get('query'),
      state: params.get('state'),
      code: params.get('code'),
    });
  }

  /**
   * Generate a code challenge
   */
  private async pkceChallengeFromVerifier() {
    const hashed = await sha256(this.getCodeVerifier());
    return encode(hashed).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Get a random string from storage or store a new one and return it's value
   * @param  {string} key
   * @return {string}
   */
  private randomStringFromStorage(key: string): string {
    const fromStorage = this.getStore().getItem(key);
    if (fromStorage === null) {
      this.getStore().setItem(key, createRandomString());
    }

    return this.getStore().getItem(key) || '';
  }

  /**
   * Validates params from auth response
   * @param  {AuthResponse} queryParams
   * @return {Promise<IAuthResponse>}
   */
  private validateAuthResponse(queryParams: IAuthResponse): Promise<IAuthResponse> {
    return new Promise<IAuthResponse>((resolve, reject) => {
      if (queryParams.error) {
        return reject({ error: queryParams.error });
      }

      if (queryParams.state !== this.getState()) {
        return reject({ error: 'Invalid State' });
      }

      return resolve(queryParams);
    });
  }

  /**
   * Get the storage (sessionStorage / localStorage) to use, defaults to sessionStorage
   * @return {Storage}
   */
  private getStore(): Storage {
    return this.config?.storage || sessionStorage;
  }
}

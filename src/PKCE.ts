import type { IAuthResponse } from './IAuthResponse';
import type { IConfig } from './IConfig';
import type { IObject } from './IObject';
import type { ITokenResponse } from './ITokenResponse';
import type { ICorsOptions } from './ICorsOptions';

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

export class PKCE {
  private config: IConfig;
  private state: string = '';
  private codeVerifier: string = '';
  private corsRequestOptions: ICorsOptions = {};

  STATE_KEY = 'pkce_state';
  CODE_VERIFIER_KEY = 'pkce_code_verifier';

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

  public resetStorageState() {
    this.getStore().removeItem(this.STATE_KEY);
    this.getStore().removeItem(this.CODE_VERIFIER_KEY);
  }

  /**
   * Given the return url, get a token from the oauth server
   * @param  url current urlwith params from server
   * @param  {object} additionalParams include additional parameters in the request body
   * @return {Promise<ITokenResponse>}
   */
  public async exchangeForAccessToken(url: string, additionalParams: IObject = {}): Promise<ITokenResponse> {
    const query = await this.parseAuthResponseUrl(url);

    const exchange = await fetch(this.config.token_endpoint, {
      method: 'POST',
      body: new URLSearchParams(
        Object.assign(
          {
            grant_type: 'authorization_code',
            code: query.code,
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
    });

    this.resetStorageState();

    return exchange.json();
  }

  /**
   * Given a refresh token, return a new token from the oauth server
   * @param  refreshTokens current refresh token from server
   * @return {Promise<ITokenResponse>}
   */
  public async refreshAccessToken(refreshToken: string): Promise<ITokenResponse> {
    const response = await fetch(this.config.token_endpoint, {
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
    });
    return response.json();
  }

  /**
   * Get the current codeVerifier or generate a new one
   * @return {string}
   */
  private getCodeVerifier(): string {
    if (this.codeVerifier === '') {
      this.codeVerifier = this.randomStringFromStorage(this.CODE_VERIFIER_KEY);
    }

    return this.codeVerifier;
  }

  /**
   * Get the current state or generate a new one
   * @return {string}
   */
  private getState(explicit: string = null): string {
    if (explicit !== null) {
      this.getStore().setItem(this.STATE_KEY, explicit);
    }

    if (this.state === '') {
      this.state = this.randomStringFromStorage(this.STATE_KEY);
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

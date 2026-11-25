/// <reference types="node" />

import { FastifyPluginAsync, FastifyRequest } from 'fastify'
import { Options as CSRFOptions } from '@fastify/csrf'
import { CookieSerializeOptions as FastifyCookieSerializeOptions } from '@fastify/cookie'

declare module 'fastify' {
  interface FastifyInstance {
    csrfProtection(req: FastifyRequest, reply: FastifyReply, done: () => void): void;
  }

  interface FastifyReply {
    /**
     * Generate a token and configure the secret if needed
     * @param options Serialize options and userInfo
     */
    generateCsrf(
      options?: fastifyCsrfProtection.CookieSerializeOptions & { userInfo?: string }
    ): string;
  }
}

type FastifyCsrfProtection =
  FastifyPluginAsync<fastifyCsrfProtection.FastifyCsrfProtectionOptions>

declare namespace fastifyCsrfProtection {
  export type CookieSerializeOptions = FastifyCookieSerializeOptions

  export type GetTokenFn = (req: FastifyRequest) => string | void

  interface FastifyCsrfProtectionOptionsBase {
    cookieKey?: string;
    cookieOpts?: CookieSerializeOptions;
    sessionKey?: string;
    getUserInfo?: (req: FastifyRequest) => string;
    getToken?: GetTokenFn;
  }

  type RequiredCSRFHmac = Omit<CSRFOptions, 'hmacKey' | 'userInfo'> &
    Required<Pick<CSRFOptions, 'hmacKey'>> & { userInfo: true }

  type OptionalCSRFNoUserInfo = Omit<CSRFOptions, 'userInfo'> & {
    userInfo?: false;
  }

  type OptionalCSRFHmac = Omit<CSRFOptions, 'userInfo'> &
    Required<Pick<CSRFOptions, 'hmacKey'>> & { userInfo?: false }

  interface FastifyCsrfProtectionOptionsFastifyCookieSigned {
    sessionPlugin?: '@fastify/cookie';
    cookieOpts: CookieSerializeOptions & { signed: true };
    csrfOpts?: OptionalCSRFNoUserInfo | RequiredCSRFHmac;
  }

  interface FastifyCsrfProtectionOptionsFastifyCookieUnsigned {
    sessionPlugin?: '@fastify/cookie';
    cookieOpts?: CookieSerializeOptions;
    csrfOpts: OptionalCSRFHmac | RequiredCSRFHmac;
  }

  type FastifyCsrfProtectionOptionsFastifyCookie =
    FastifyCsrfProtectionOptionsFastifyCookieSigned |
    FastifyCsrfProtectionOptionsFastifyCookieUnsigned

  interface FastifyCsrfProtectionOptionsFastifySession {
    sessionPlugin: '@fastify/session';
    csrfOpts?: CSRFOptions;
  }

  interface FastifyCsrfProtectionOptionsFastifySecureSession {
    sessionPlugin: '@fastify/secure-session';
    csrfOpts?: CSRFOptions;
  }

  export type FastifyCsrfProtectionOptions = FastifyCsrfProtectionOptionsBase & (
    FastifyCsrfProtectionOptionsFastifyCookie |
    FastifyCsrfProtectionOptionsFastifySession |
    FastifyCsrfProtectionOptionsFastifySecureSession
  )

  export const fastifyCsrfProtection: FastifyCsrfProtection
  export { fastifyCsrfProtection as default }
}

declare function fastifyCsrfProtection (...params: Parameters<FastifyCsrfProtection>): ReturnType<FastifyCsrfProtection>
export = fastifyCsrfProtection

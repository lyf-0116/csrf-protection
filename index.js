'use strict'

const assert = require('node:assert')
const fp = require('fastify-plugin')
const CSRF = require('@fastify/csrf')
const createError = require('@fastify/error')

const MissingCSRFSecretError = createError('FST_CSRF_MISSING_SECRET', 'Missing csrf secret', 403)
const InvalidCSRFTokenError = createError('FST_CSRF_INVALID_TOKEN', 'Invalid csrf token', 403)
const MultipleCSRFTokenSourcesError = createError(
  'FST_CSRF_MULTIPLE_TOKEN_SOURCES',
  'Conflicting CSRF tokens in request sources',
  403
)

const defaultOptions = {
  cookieKey: '_csrf',
  cookieOpts: { path: '/', sameSite: true, httpOnly: true },
  sessionKey: '_csrf',
  getToken: getTokenDefault,
  getUserInfo: getUserInfoDefault,
  sessionPlugin: '@fastify/cookie',
  logLevel: 'warn'
}

async function fastifyCsrfProtection (fastify, opts) {
  const {
    cookieKey,
    cookieOpts,
    sessionKey,
    getToken,
    getUserInfo,
    sessionPlugin,
    logLevel
  } = Object.assign({}, defaultOptions, opts)

  const csrfOpts = opts?.csrfOpts ? opts.csrfOpts : {}

  assert(typeof cookieKey === 'string', 'cookieKey should be a string')
  assert(typeof sessionKey === 'string', 'sessionKey should be a string')
  assert(typeof getToken === 'function', 'getToken should be a function')
  assert(typeof getUserInfo === 'function', 'getUserInfo should be a function')
  assert(typeof cookieOpts === 'object', 'cookieOpts should be a object')
  assert(typeof logLevel === 'string', 'logLevel should be a string')
  assert(
    ['@fastify/cookie', '@fastify/session', '@fastify/secure-session'].includes(sessionPlugin),
    "sessionPlugin should be one of the following: '@fastify/cookie', '@fastify/session', '@fastify/secure-session'"
  )

  if (opts.getUserInfo) {
    csrfOpts.userInfo = true
  }

  if (sessionPlugin === '@fastify/cookie' && csrfOpts.userInfo) {
    assert(csrfOpts.hmacKey, 'csrfOpts.hmacKey is required')
  }

  const tokens = new CSRF(csrfOpts)

  const isCookieSigned = cookieOpts?.signed

  if (sessionPlugin === '@fastify/secure-session') {
    fastify.decorateReply('generateCsrf', generateCsrfSecureSession)
  } else if (sessionPlugin === '@fastify/session') {
    fastify.decorateReply('generateCsrf', generateCsrfSession)
  } else {
    fastify.decorateReply('generateCsrf', generateCsrfCookie)
  }

  fastify.decorate('csrfProtection', csrfProtection)

  let getSecret

  if (sessionPlugin === '@fastify/secure-session') {
    getSecret = function getSecret (req, _reply) { return req.session.get(sessionKey) }
  } else if (sessionPlugin === '@fastify/session') {
    getSecret = function getSecret (req, _reply) { return req.session[sessionKey] }
  } else {
    getSecret = function getSecret (req, reply) {
      return isCookieSigned
        ? reply.unsignCookie(req.cookies[cookieKey] || '').value
        : req.cookies[cookieKey]
    }
  }

  function generateCsrfCookie (opts) {
    let secret = isCookieSigned
      ? this.unsignCookie(this.request.cookies[cookieKey] || '').value
      : this.request.cookies[cookieKey]
    const userInfo = opts ? opts.userInfo : undefined
    if (!secret) {
      secret = tokens.secretSync()
      this.setCookie(cookieKey, secret, Object.assign({}, cookieOpts, opts))
    }
    return tokens.create(secret, userInfo)
  }

  function generateCsrfSecureSession (opts) {
    let secret = this.request.session.get(sessionKey)
    if (!secret) {
      secret = tokens.secretSync()
      this.request.session.set(sessionKey, secret)
    }
    const userInfo = opts ? opts.userInfo : undefined
    if (opts) {
      this.request.session.options(opts)
    }
    return tokens.create(secret, userInfo)
  }

  function generateCsrfSession (opts) {
    let secret = this.request.session[sessionKey]
    const userInfo = opts ? opts.userInfo : undefined
    if (!secret) {
      secret = tokens.secretSync()
      this.request.session[sessionKey] = secret
    }
    return tokens.create(secret, userInfo)
  }

  function csrfProtection (req, reply, next) {
    const secret = getSecret(req, reply)
    if (!secret) {
      req.log[logLevel]('Missing csrf secret')
      return reply.send(new MissingCSRFSecretError())
    }

    let token
    try {
      token = getToken(req)
    } catch (error) {
      if (error instanceof MultipleCSRFTokenSourcesError) {
        req.log[logLevel](
          { tokenSources: error.tokenSources },
          'Conflicting csrf tokens'
        )
        return reply.send(new InvalidCSRFTokenError())
      }
      return next(error)
    }

    if (!tokens.verify(secret, token, getUserInfo(req))) {
      req.log[logLevel]('Invalid csrf token')
      return reply.send(new InvalidCSRFTokenError())
    }
    next()
  }
}

function getTokenDefault (req) {
  const tokenSources = [
    ['body._csrf', req.body?._csrf],
    ['header.csrf-token', req.headers['csrf-token']],
    ['header.xsrf-token', req.headers['xsrf-token']],
    ['header.x-csrf-token', req.headers['x-csrf-token']],
    ['header.x-xsrf-token', req.headers['x-xsrf-token']]
  ]

  const providedTokens = []
  const providedSourceNames = []
  for (const [sourceName, token] of tokenSources) {
    if (token) {
      providedTokens.push(token)
      providedSourceNames.push(sourceName)
    }
  }

  if (providedTokens.length > 1) {
    const [firstToken] = providedTokens
    if (!providedTokens.every(token => token === firstToken)) {
      const error = new MultipleCSRFTokenSourcesError()
      error.tokenSources = providedSourceNames
      throw error
    }
  }

  return providedTokens[0]
}

function getUserInfoDefault (_req) {
  return undefined
}

module.exports = fp(fastifyCsrfProtection, {
  fastify: '5.x',
  name: '@fastify/csrf-protection'
})
module.exports.default = fastifyCsrfProtection
module.exports.fastifyCsrfProtection = fastifyCsrfProtection

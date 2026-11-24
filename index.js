'use strict'

const assert = require('node:assert')
const fp = require('fastify-plugin')
const CSRF = require('@fastify/csrf')
const createError = require('@fastify/error')

const MissingCSRFSecretError = createError('FST_CSRF_MISSING_SECRET', 'Missing csrf secret', 403)
const InvalidCSRFTokenError = createError('FST_CSRF_INVALID_TOKEN', 'Invalid csrf token', 403)
const MissingUserInfoError = createError('FST_CSRF_MISSING_USER_INFO', 'Missing csrf userInfo', 403)

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

  let getSecret
  let saveSecret
  let applyStoreOptions

  if (sessionPlugin === '@fastify/secure-session') {
    getSecret = function getSecret (req) { return req.session.get(sessionKey) }
    saveSecret = function saveSecret (req, _reply, secret) { req.session.set(sessionKey, secret) }
    applyStoreOptions = function applyStoreOptions (req, opts) { req.session.options(opts) }
  } else if (sessionPlugin === '@fastify/session') {
    getSecret = function getSecret (req) { return req.session[sessionKey] }
    saveSecret = function saveSecret (req, _reply, secret) { req.session[sessionKey] = secret }
    applyStoreOptions = function applyStoreOptions () {}
  } else {
    getSecret = function getSecret (req, reply) {
      return isCookieSigned
        ? reply.unsignCookie(req.cookies[cookieKey] || '').value
        : req.cookies[cookieKey]
    }
    saveSecret = function saveSecret (_req, reply, secret, opts) {
      reply.setCookie(cookieKey, secret, Object.assign({}, cookieOpts, opts))
    }
    applyStoreOptions = function applyStoreOptions () {}
  }

  fastify.decorate('csrfProtection', csrfProtection)

  fastify.decorateReply('generateCsrf', generateCsrf)

  function generateCsrf (opts) {
    const userInfo = opts ? opts.userInfo : undefined
    if (csrfOpts.userInfo && typeof userInfo !== 'string') {
      throw new MissingUserInfoError()
    }
    const storeOptions = opts ? Object.fromEntries(Object.entries(opts).filter(([key]) => key !== 'userInfo')) : undefined

    let secret = getSecret(this.request, this)
    if (!secret) {
      secret = tokens.secretSync()
      saveSecret(this.request, this, secret, storeOptions)
    }
    if (storeOptions) {
      applyStoreOptions(this.request, storeOptions)
    }
    return tokens.create(secret, userInfo)
  }

  function csrfProtection (req, reply, next) {
    const secret = getSecret(req, reply)
    if (!secret) {
      req.log[logLevel]('Missing csrf secret')
      return reply.send(new MissingCSRFSecretError())
    }
    const userInfo = getUserInfo(req)
    if (csrfOpts.userInfo && typeof userInfo !== 'string') {
      req.log[logLevel]('Missing csrf userInfo')
      return reply.send(new MissingUserInfoError())
    }
    if (!tokens.verify(secret, getToken(req), userInfo)) {
      req.log[logLevel]('Invalid csrf token')
      return reply.send(new InvalidCSRFTokenError())
    }
    next()
  }
}

function getTokenDefault (req) {
  return req.body?._csrf ||
    req.headers['csrf-token'] ||
    req.headers['xsrf-token'] ||
    req.headers['x-csrf-token'] ||
    req.headers['x-xsrf-token']
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

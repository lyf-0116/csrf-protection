'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyCookie = require('@fastify/cookie')
const CSRF = require('@fastify/csrf')
const fastifyCsrf = require('../')

const hmacKey = 'server-side-hmac-key-with-enough-entropy'
const cookieSecret = 'server-side-cookie-signing-secret'

test('Unsigned cookie with HMAC key rejects attacker-chosen secrets', async t => {
  const fastify = Fastify()
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf, { csrfOpts: { hmacKey } })
  await ready(fastify)

  const { cookie, token } = await getToken(fastify)
  let response = await post(fastify, cookie, token)
  t.assert.strictEqual(response.statusCode, 200)

  const attackerTokens = new CSRF()
  const attackerSecret = attackerTokens.secretSync()
  const attackerToken = attackerTokens.create(attackerSecret)

  response = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: {
      'csrf-token': attackerToken
    },
    cookies: {
      _csrf: attackerSecret
    }
  })

  t.assert.strictEqual(response.statusCode, 403)
  t.assert.strictEqual(response.json().message, 'Invalid csrf token')
})

test('Signed cookie rejects attacker-chosen secrets', async t => {
  const fastify = Fastify()
  await fastify.register(fastifyCookie, { secret: cookieSecret })
  await fastify.register(fastifyCsrf, { cookieOpts: { signed: true } })
  await ready(fastify)

  const { cookie, token } = await getToken(fastify)
  let response = await post(fastify, cookie, token)
  t.assert.strictEqual(response.statusCode, 200)

  const attackerTokens = new CSRF()
  const attackerSecret = attackerTokens.secretSync()
  const attackerToken = attackerTokens.create(attackerSecret)

  response = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: {
      'csrf-token': attackerToken
    },
    cookies: {
      _csrf: attackerSecret
    }
  })

  t.assert.strictEqual(response.statusCode, 403)
  t.assert.strictEqual(response.json().message, 'Missing csrf secret')
})

async function ready (fastify) {
  fastify.get('/', async (_req, reply) => {
    return { token: reply.generateCsrf() }
  })
  fastify.post('/', { onRequest: fastify.csrfProtection }, async (req) => {
    return req.body
  })
  await fastify.ready()
}

async function getToken (fastify) {
  const response = await fastify.inject({
    method: 'GET',
    path: '/'
  })
  return {
    cookie: response.cookies[0],
    token: response.json().token
  }
}

function post (fastify, cookie, token) {
  return fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: {
      'csrf-token': token
    },
    cookies: {
      [cookie.name]: cookie.value
    }
  })
}

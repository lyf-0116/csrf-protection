'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyCookie = require('@fastify/cookie')
const fastifyCsrf = require('../')

async function load (options = {}) {
  const fastify = Fastify()
  await fastify.register(fastifyCookie)
  await fastify.register(fastifyCsrf, options)

  fastify.get('/', async (_req, reply) => {
    return { token: reply.generateCsrf() }
  })

  fastify.post('/', { preValidation: fastify.csrfProtection }, async (req) => {
    return req.body
  })

  await fastify.ready()
  return fastify
}

async function getCredentials (fastify) {
  const response = await fastify.inject({ method: 'GET', path: '/' })
  return {
    cookie: response.cookies[0],
    token: response.json().token
  }
}

test('accepts matching tokens from every default source', async t => {
  const fastify = await load()
  const { cookie, token } = await getCredentials(fastify)

  const response = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world', _csrf: token },
    headers: {
      'csrf-token': token,
      'xsrf-token': token,
      'x-csrf-token': token,
      'x-xsrf-token': token
    },
    cookies: {
      [cookie.name]: cookie.value
    }
  })

  t.assert.strictEqual(response.statusCode, 200)
  t.assert.strictEqual(response.json().hello, 'world')
})

test('rejects conflicting body and header tokens without using source priority', async t => {
  const fastify = await load()
  const { cookie, token } = await getCredentials(fastify)

  const response = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { _csrf: token },
    headers: {
      'csrf-token': 'different-token'
    },
    cookies: {
      [cookie.name]: cookie.value
    }
  })

  t.assert.strictEqual(response.statusCode, 403)
  t.assert.strictEqual(response.json().message, 'Invalid csrf token')
})

test('rejects conflicting header tokens even when the first source is valid', async t => {
  const fastify = await load()
  const { cookie, token } = await getCredentials(fastify)

  const response = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    headers: {
      'csrf-token': token,
      'x-csrf-token': 'different-token'
    },
    cookies: {
      [cookie.name]: cookie.value
    }
  })

  t.assert.strictEqual(response.statusCode, 403)
  t.assert.strictEqual(response.json().message, 'Invalid csrf token')
})

test('preserves errors thrown by a custom getToken function', async t => {
  const fastify = await load({
    getToken () {
      throw new Error('token extraction failed')
    }
  })
  const { cookie } = await getCredentials(fastify)

  const response = await fastify.inject({
    method: 'POST',
    path: '/',
    payload: { hello: 'world' },
    cookies: {
      [cookie.name]: cookie.value
    }
  })

  t.assert.strictEqual(response.statusCode, 500)
  t.assert.strictEqual(response.json().message, 'token extraction failed')
})

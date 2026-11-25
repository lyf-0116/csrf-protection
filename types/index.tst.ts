import Fastify from 'fastify'
import FastifyCookie from '@fastify/cookie'
import FastifyCsrfProtection from '..'
import { expect } from 'tstyche'
import FastifySession from '@fastify/session'

const fastify = Fastify()

declare module 'fastify' {
  interface Session {
    username: string;
  }
}

async function run () {
  await fastify.register(FastifyCookie, { secret: 'a secret with minimum length of 32 characters' })
  await fastify.register(FastifyCsrfProtection, { cookieOpts: { signed: true } })

  fastify.route({
    method: 'GET',
    url: '/',
    handler: async (_req, reply) => {
      const token = reply.generateCsrf()
      const tokenWithOpts = reply.generateCsrf({ userInfo: 'any-string' })
      expect(token).type.toBe<string>()
      expect(tokenWithOpts).type.toBe<string>()
      return token
    }
  })

  fastify.route({
    method: 'POST',
    url: '/',
    onRequest: fastify.csrfProtection,
    handler: async (req) => {
      return { ok: true }
    }
  })

  fastify.addHook('onRequest', fastify.csrfProtection)
}
run()

fastify.register(FastifyCsrfProtection, {
  csrfOpts: { algorithm: 'sha1', hmacKey: 'hmac' }
})

expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  csrfOpts: { algorithm: 1 }
})

fastify.register(FastifySession, {
  secret: 'a secret with minimum length of 32 characters'
})
fastify.register(FastifyCsrfProtection, {
  csrfOpts: {
    hmacKey: '123'
  },
  getUserInfo (req) {
    const info = req.session.get('username')
    if (info) {
      return info
    } else {
      throw new Error('No user info')
    }
  }
})

expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  getUserInfo: 'invalid'
})

fastify.register(FastifyCsrfProtection, {
  csrfOpts: { hmacKey: 'hmac' },
  sessionPlugin: '@fastify/cookie'
})
fastify.register(FastifyCsrfProtection, { csrfOpts: { hmacKey: 'hmac' } })
fastify.register(FastifyCsrfProtection, { cookieOpts: { signed: true } })
fastify.register(FastifyCsrfProtection, {
  cookieOpts: { signed: true, path: '/' },
  csrfOpts: { algorithm: 'sha1' }
})
fastify.register(FastifyCsrfProtection, {
  cookieOpts: { signed: false },
  csrfOpts: { hmacKey: 'hmac' }
})

expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {})
expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, { csrfOpts: {} })
expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  cookieOpts: { signed: false }
})
expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  cookieOpts: { path: '/' }
})
expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  csrfOpts: { algorithm: 'sha1' }
})

expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  csrfOpts: { userInfo: true },
  sessionPlugin: '@fastify/cookie'
})

fastify.register(FastifyCsrfProtection, {
  sessionPlugin: '@fastify/cookie',
  csrfOpts: { userInfo: true, hmacKey: 'key' }
})
fastify.register(FastifyCsrfProtection, {
  csrfOpts: {},
  sessionPlugin: '@fastify/session'
})
fastify.register(FastifyCsrfProtection, {
  csrfOpts: {},
  sessionPlugin: '@fastify/secure-session'
})
fastify.register(FastifyCsrfProtection, { sessionPlugin: '@fastify/session' })
fastify.register(FastifyCsrfProtection, {
  sessionPlugin: '@fastify/secure-session'
})
fastify.register(FastifyCsrfProtection, {
  logLevel: 'info',
  csrfOpts: { hmacKey: 'hmac' }
})

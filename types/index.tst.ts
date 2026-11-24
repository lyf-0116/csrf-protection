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
  await fastify.register(FastifyCookie)
  await fastify.register(FastifyCsrfProtection, { userInfoBinding: false })

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
  csrfOpts: { algorithm: 'sha1', hmacKey: 'hmac' },
  userInfoBinding: false
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
  sessionPlugin: '@fastify/cookie',
  userInfoBinding: false
})
fastify.register(FastifyCsrfProtection, { csrfOpts: { hmacKey: 'hmac' }, userInfoBinding: false })
fastify.register(FastifyCsrfProtection, { userInfoBinding: false })
fastify.register(FastifyCsrfProtection, { csrfOpts: {}, userInfoBinding: false })

expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  csrfOpts: { userInfo: true },
  sessionPlugin: '@fastify/cookie'
})

fastify.register(FastifyCsrfProtection, {
  sessionPlugin: '@fastify/cookie',
  csrfOpts: { userInfo: true, hmacKey: 'key' },
  getUserInfo: () => 'user-info'
})
fastify.register(FastifyCsrfProtection, { sessionPlugin: '@fastify/cookie', userInfoBinding: false })
fastify.register(FastifyCsrfProtection, {
  csrfOpts: {},
  sessionPlugin: '@fastify/session',
  userInfoBinding: false
})
fastify.register(FastifyCsrfProtection, {
  csrfOpts: {},
  sessionPlugin: '@fastify/secure-session',
  userInfoBinding: false
})
fastify.register(FastifyCsrfProtection, { sessionPlugin: '@fastify/session', userInfoBinding: false })
fastify.register(FastifyCsrfProtection, {
  sessionPlugin: '@fastify/secure-session',
  userInfoBinding: false
})
fastify.register(FastifyCsrfProtection, { logLevel: 'info', userInfoBinding: false })

// userInfoBinding defaults to true and requires getUserInfo
expect(fastify.register).type.not.toBeCallableWith(FastifyCsrfProtection, {
  userInfoBinding: true
})
fastify.register(FastifyCsrfProtection, {
  userInfoBinding: true,
  csrfOpts: { hmacKey: 'hmac' },
  getUserInfo: () => 'user-info'
})

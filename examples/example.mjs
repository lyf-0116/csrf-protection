import Fastify from 'fastify'
import fastifyCookie from '@fastify/cookie'
import fastifyCsrfProtection from '../index.js'
import { randomBytes } from 'node:crypto'

const fastify = Fastify({
  logger: true
})

// Generate a key for this demo. Production deployments should use a stable
// secret from an external secret store instead.
fastify.register(fastifyCookie, { secret: randomBytes(32).toString('hex') })
await fastify.register(fastifyCsrfProtection, { cookieOpts: { signed: true } })

fastify.post(
  '/',
  {
    preHandler: fastify.csrfProtection
  },
  async (req) => {
    return req.body
  }
)

// generate a token
fastify.route({
  method: 'GET',
  url: '/',
  handler: async (_req, reply) => {
    const token = reply.generateCsrf()
    reply.type('text/html')

    return `
      <html>
        <script type='text/javascript'>
          async function test(event) {
            event.preventDefault()
            const rawResponse = await fetch('/', {
              method: 'POST',
              headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ _csrf: '${token}'})
            });
            const content = await rawResponse.json();

            alert(JSON.stringify(content));
          }
        </script>
        <body>
          <form action="/" method='POST' id='form' onsubmit={test(event)}>
            <input type='submit' value='submit' />
          </form>
        </body>
      </html>

    `
  }
})

// Run the server!
fastify.listen({ port: 3001 }, function (err) {
  if (err) {
    fastify.log.error(err)
    process.exit(1)
  }
})

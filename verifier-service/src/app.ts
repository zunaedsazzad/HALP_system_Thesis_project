import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyCors from '@fastify/cors';
import path from 'path';
import authRoutes from './routes/auth-challenge';
import proofRoutes from './routes/proof-verification';

console.log('\n╔════════════════════════════════════════╗');
console.log('║   HALP VERIFIER SERVICE STARTING...   ║');
console.log('╚════════════════════════════════════════╝\n');

const server = Fastify({ logger: false });

// Enable CORS
server.register(fastifyCors, { origin: true });

// Serve static files from public directory
server.register(fastifyStatic, {
  root: path.join(__dirname, '../public'),
  prefix: '/',
});

// Health check endpoint
server.get('/health', async () => {
  return { status: 'ok', service: 'verifier', timestamp: Date.now() };
});

server.register(authRoutes, { prefix: '/auth' });
server.register(proofRoutes, { prefix: '/proof' });  // Changed from /proofs to /proof

// Serve UI on root
server.get('/', async (request, reply) => {
  return reply.sendFile('index.html');
});

const port = process.env.PORT ? Number(process.env.PORT) : 3002;

server.listen({ port, host: '0.0.0.0' })
  .then(() => {
    console.log('\n╔════════════════════════════════════════╗');
    console.log('║   VERIFIER SERVICE READY              ║');
    console.log('╚════════════════════════════════════════╝');
    console.log(`\n🚀 Server listening at http://localhost:${port}`);
    console.log(`\n🌐 Web UI: http://localhost:${port}`);
    console.log('\nAuthentication Endpoints (HALP Protocol):');
    console.log('  POST /auth/challenge       - Generate auth challenge (Phase 1)');
    console.log('  GET  /auth/challenge       - Quick challenge (default domain)');
    console.log('  POST /auth/verify          - Verify proof & issue token (Phase 4)');
    console.log('\nCredential Verification Endpoints:');
    console.log('  POST /proof/verify         - Verify W3C Verifiable Credential');
    console.log('  POST /proof/verify/hybrid  - Verify hybrid SNARK+BBS+ proof');
    console.log('  GET  /proof/verify/hybrid/status - Get verifier status');
    console.log('\nReady to process requests...\n');
  })
  .catch(err => {
    console.error('Failed to start verifier service:', err);
    process.exit(1);
  });

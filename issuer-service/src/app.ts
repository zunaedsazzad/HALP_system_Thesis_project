import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyCors from '@fastify/cors';
import path from 'path';
import credentialRoutes from './routes/credential-issuance';
import didRoutes from './routes/did-management';

console.log('\n╔════════════════════════════════════════╗');
console.log('║   HALP ISSUER SERVICE STARTING...     ║');
console.log('╚════════════════════════════════════════╝\n');

const server = Fastify({ logger: false });

// Enable CORS for frontend access
server.register(fastifyCors, {
  origin: true
});

// Serve static files (issuer UI)
server.register(fastifyStatic, {
  root: path.join(__dirname, '../public'),
  prefix: '/',
});

server.register(credentialRoutes, { prefix: '/credentials' });
server.register(didRoutes, { prefix: '/did' });

// Serve issuer UI on root
server.get('/', async (request, reply) => {
  return reply.sendFile('index.html');
});

const port = process.env.PORT ? Number(process.env.PORT) : 3001;

server.listen({ port, host: '0.0.0.0' })
  .then(() => {
    console.log('\n╔════════════════════════════════════════╗');
    console.log('║   ISSUER SERVICE READY                ║');
    console.log('╚════════════════════════════════════════╝');
    console.log(`\n🚀 Server listening at http://localhost:${port}`);
    console.log('\nAvailable endpoints:');
    console.log('  POST /credentials/request  - Submit credential request (pending approval)');
    console.log('  GET  /credentials/pending  - Get pending requests');
    console.log('  POST /credentials/approve  - Approve and sign a request');
    console.log('  POST /credentials/reject   - Reject a request');
    console.log('  GET  /credentials/status/:id - Check credential status');
    console.log('  POST /did/create           - Create new DID');
    console.log('  GET  /did/resolve/:did     - Resolve DID document');
    console.log('\n🖥️  Issuer UI available at: http://localhost:' + port);
    console.log('\nReady to process requests...\n');
  })
  .catch(err => {
    console.error('Failed to start issuer service:', err);
    process.exit(1);
  });

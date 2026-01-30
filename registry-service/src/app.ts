import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import path from 'path';
import nullifierRoutes from './routes/nullifier-check';
import merkleRoutes from './routes/merkle-proof';
import merkleTree from './services/indexed-merkle-tree';

console.log('\n╔════════════════════════════════════════╗');
console.log('║   HALP REGISTRY SERVICE STARTING...   ║');
console.log('╚════════════════════════════════════════╝\n');

const server = Fastify({ logger: false });

// Serve static files from public folder
server.register(fastifyStatic, {
  root: path.join(__dirname, '..', 'public'),
  prefix: '/'
});

// Enable CORS for development
server.addHook('onRequest', async (request, reply) => {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  reply.header('Access-Control-Allow-Headers', 'Content-Type');
  if (request.method === 'OPTIONS') {
    reply.status(204).send();
  }
});

server.register(nullifierRoutes, { prefix: '/nullifiers' });
server.register(merkleRoutes, { prefix: '/merkle' });

const port = process.env.PORT ? Number(process.env.PORT) : 3003;

// Initialize the Merkle tree with Poseidon, then start the server
async function start() {
  try {
    console.log('  Initializing Merkle tree with Poseidon hash...');
    await merkleTree.initialize();
    console.log('  ✔ Merkle tree initialized');
    
    await server.listen({ port, host: '0.0.0.0' });
    console.log('\n╔════════════════════════════════════════╗');
    console.log('║   REGISTRY SERVICE READY              ║');
    console.log('╚════════════════════════════════════════╝');
    console.log(`\n🚀 Server listening at http://localhost:${port}`);
    console.log(`🌳 Merkle Tree UI: http://localhost:${port}`);
    console.log('\nNullifier Registry Endpoints:');
    console.log('  POST /nullifiers/check     - Check if nullifier used');
    console.log('  POST /nullifiers/register  - Register new nullifier');
    console.log('  GET  /nullifiers/stats     - Registry statistics');
    console.log('\nMerkle Tree Endpoints:');
    console.log('  GET  /merkle/root          - Get current Merkle root');
    console.log('  POST /merkle/proof         - Generate membership/non-membership proof');
    console.log('  POST /merkle/verify        - Verify a Merkle proof');
    console.log('  GET  /merkle/stats         - Tree statistics');
    console.log('\nReady to process requests...\n');
  } catch (err) {
    console.error('Failed to start registry service:', err);
    process.exit(1);
  }
}

start();

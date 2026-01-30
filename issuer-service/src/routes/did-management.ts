import { FastifyPluginAsync } from 'fastify';
import didManager from '../services/did-manager';

const didRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.post('/create', async (request, reply) => {
    console.log('\n========== DID CREATION REQUEST ==========');
    const { did, doc } = await didManager.createDid();
    console.log('========== DID CREATED ==========\n');
    return { did, doc };
  });

  fastify.get('/resolve/:did', async (request, reply) => {
    console.log('\n========== DID RESOLUTION REQUEST ==========');
    const { did } = (request.params as any);
    console.log('Requested DID:', did);
    const doc = await didManager.resolve(did);
    if (!doc) {
      console.log('❌ DID not found');
      console.log('========== RESOLUTION FAILED ==========\n');
      return reply.status(404).send({ error: 'not found' });
    }
    console.log('✓ DID document returned');
    console.log('========== RESOLUTION COMPLETE ==========\n');
    return doc;
  });
};

export default didRoutes;

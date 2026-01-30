import * as jwt from 'jsonwebtoken';

const SECRET: jwt.Secret = process.env.JWT_SECRET || 'dev-secret';

export class JwtManager {
  sign(payload: object, expiresIn: jwt.SignOptions['expiresIn'] = '1h') {
    return jwt.sign(payload, SECRET, { expiresIn });
  }

  // Verify either with a publicKey PEM (asymmetric RS256) or fall back to symmetric secret
  verify(token: string, publicKeyPem?: string) {
    try {
      if (publicKeyPem) {
        return jwt.verify(token, publicKeyPem as jwt.Secret, { algorithms: ['RS256'] });
      }
      return jwt.verify(token, SECRET);
    } catch (e) {
      return null;
    }
  }
}

export default new JwtManager();

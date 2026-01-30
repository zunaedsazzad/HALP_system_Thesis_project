import * as jwt from 'jsonwebtoken';

// JwtManager supports both symmetric (HMAC) signing via JWT_SECRET and
// asymmetric signing via a provided private key PEM (RS256).
const SECRET: jwt.Secret = process.env.JWT_SECRET || 'dev-secret';

export class JwtManager {
  sign(payload: string | object | Buffer, expiresIn: string | number = '1h', privateKeyPem?: string): string {
    if (privateKeyPem) {
      return jwt.sign(payload as any, privateKeyPem as jwt.Secret, { algorithm: 'RS256', expiresIn } as jwt.SignOptions);
    }
    return jwt.sign(payload as any, SECRET as jwt.Secret, { expiresIn } as jwt.SignOptions);
  }

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

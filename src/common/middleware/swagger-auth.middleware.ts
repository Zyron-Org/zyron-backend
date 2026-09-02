import { Request, Response, NextFunction } from 'express';

export function swaggerAuth(username: string, password: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Basic ')) {
      res.set('WWW-Authenticate', 'Basic realm="Swagger UI Authentication Required"');
      return res.status(401).send('Authentication required to access Zyron API Documentation.');
    }

    try {
      const base64Credentials = authHeader.split(' ')[1];
      const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii').split(':');
      const reqUser = credentials[0];
      const reqPass = credentials.slice(1).join(':'); // handles passwords with colons

      if (reqUser !== username || reqPass !== password) {
        res.set('WWW-Authenticate', 'Basic realm="Swagger UI Authentication Required"');
        return res.status(401).send('Authentication required to access Zyron API Documentation.');
      }

      return next();
    } catch (e) {
      res.set('WWW-Authenticate', 'Basic realm="Swagger UI Authentication Required"');
      return res.status(401).send('Invalid authorization header format');
    }
  };
}

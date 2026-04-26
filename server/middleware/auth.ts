import { Request, Response, NextFunction } from 'express';
import { User } from '../models/User.ts';
import { createClient } from '@supabase/supabase-js';

export interface AuthRequest extends Request {
  user?: any;
}

let supabase: any = null;

export const protect = async (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!supabase) {
    const supabaseUrl = process.env.VITE_SUPABASE_URL || '';
    const supabaseAnonKey = process.env.VITE_SUPABASE_ANON_KEY || '';
    if (!supabaseUrl || !supabaseAnonKey) {
      return res.status(500).json({ message: 'Supabase configuration is missing in the backend' });
    }
    supabase = createClient(supabaseUrl, supabaseAnonKey);
  }

  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      
      // Verify token with Supabase - this is a secure server-side check
      const { data: { user: supabaseUser }, error } = await supabase.auth.getUser(token);
      
      if (error || !supabaseUser) {
        throw new Error('Supabase verification failed');
      }

      // Find or create local user. 
      // CRITICAL: Role is managed by our DB, NOT by user-updatable metadata.
      let localUser = await User.findOne({ email: supabaseUser.email });
      
      const adminEmail = 'eaasante333@gmail.com';

      if (!localUser) {
        // First time login - assign default role or Admin if it's the owner
        localUser = await User.create({
          name: supabaseUser.user_metadata?.name || supabaseUser.email?.split('@')[0] || 'User',
          email: supabaseUser.email,
          password: 'SUPABASE_MANAGED_ACCOUNT', // Placeholder, not used for login
          role: supabaseUser.email === adminEmail ? 'Admin' : 'Student',
        });
      } else {
        // Ensure owner always has Admin status
        if (supabaseUser.email === adminEmail && localUser.role !== 'Admin') {
          localUser.role = 'Admin';
          await localUser.save();
        }
      }

      req.user = localUser;
      next();
      return;
    } catch (error) {
      console.error('Auth middleware error:', error);
      res.status(401).json({ message: 'Not authorized, token failed' });
      return;
    }
  }

  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
    return;
  }
};

export const authorize = (...roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: `User role ${req.user?.role} is not authorized to access this route` });
    }
    next();
  };
};

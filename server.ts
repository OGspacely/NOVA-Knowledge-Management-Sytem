import * as dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
import express from 'express';
import { createServer as createViteServer } from 'vite';
import cors from 'cors';
import path from 'path';
import { connectDB } from './server/db.ts';
import authRoutes from './server/routes/auth.ts';
import articleRoutes from './server/routes/articles.ts';
import commentRoutes from './server/routes/comments.ts';
import searchRoutes from './server/routes/search.ts';
import adminRoutes from './server/routes/admin.ts';
import analyticsRoutes from './server/routes/analytics.ts';
import userRoutes from './server/routes/users.ts';
import forumRoutes from './server/routes/forum.ts';
import assignmentRoutes from './server/routes/assignments.ts';
import announcementRoutes from './server/routes/announcements.ts';
import feedbackRoutes from './server/routes/feedback.ts';
import { notificationRoutes } from './server/routes/notifications.ts';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Connect to MongoDB
  await connectDB();

  // Serve uploads directory
  app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

  // API Routes
  app.use('/api/auth', authRoutes);
  app.use('/api/articles', articleRoutes);
  app.use('/api/comments', commentRoutes);
  app.use('/api/search', searchRoutes);
  app.use('/api/admin', adminRoutes);
  app.use('/api/analytics', analyticsRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/forum', forumRoutes);
  app.use('/api/assignments', assignmentRoutes);
  app.use('/api/announcements', announcementRoutes);
  app.use('/api/feedback', feedbackRoutes);
  app.use('/api/notifications', notificationRoutes);

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();

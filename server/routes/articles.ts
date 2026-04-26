import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Article } from '../models/Article.ts';
import { AuditLog } from '../models/AuditLog.ts';
import { protect, authorize, AuthRequest } from '../middleware/auth.ts';

import { z } from 'zod';
import { validate } from '../middleware/validate.ts';

const articleSchema = z.object({
  body: z.object({
    title: z.string().min(5, 'Title must be at least 5 characters'),
    content: z.string().min(20, 'Content must be at least 20 characters'),
    subject: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid subject ID'),
    topic: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid topic ID').optional(),
    gradeLevel: z.string(),
    tags: z.union([z.string(), z.array(z.string())]).optional(),
    youtubeLinks: z.string().optional(),
    submitForReview: z.union([z.string(), z.boolean()]).optional(),
  }),
});

const router = express.Router();

// Ensure uploads directory exists
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf' || file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only PDFs and images are allowed'));
    }
  }
});

// Get all approved articles (public for logged in users)
router.get('/', protect, async (req, res) => {
  try {
    const articles = await Article.find({ status: 'Approved' })
      .populate('author', 'name')
      .populate('subject', 'name')
      .populate('topic', 'name')
      .sort('-createdAt');
    res.json(articles);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Get pending articles (Admin/Teacher only)
router.get('/pending', protect, authorize('Admin', 'Teacher'), async (req, res) => {
  try {
    const articles = await Article.find({ status: 'Pending' })
      .populate('author', 'name')
      .populate('subject', 'name')
      .populate('topic', 'name')
      .sort('createdAt');
    res.json(articles);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Get single article
router.get('/:id', protect, async (req, res) => {
  try {
    const article = await Article.findById(req.params.id)
      .populate('author', 'name')
      .populate('subject', 'name')
      .populate('topic', 'name');
    
    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    // Increment views
    article.views += 1;
    await article.save();

    res.json(article);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Create article (Teacher/Student/Admin)
router.post('/', protect, validate(articleSchema), upload.array('files', 5), async (req: AuthRequest, res) => {
  try {
    const files = req.files as Express.Multer.File[];
    const attachments = files ? files.map(file => ({
      name: file.originalname,
      url: `/uploads/${file.filename}`,
      type: file.mimetype
    })) : [];

    const articleData = { ...req.body };
    if (!articleData.topic) {
      delete articleData.topic;
    }

    let youtubeLinks = [];
    if (req.body.youtubeLinks) {
      try {
        youtubeLinks = typeof req.body.youtubeLinks === 'string' 
          ? JSON.parse(req.body.youtubeLinks) 
          : req.body.youtubeLinks;
      } catch (e) {
        // Fallback or ignore malformed JSON
      }
    }

    const article = new Article({
      ...articleData,
      tags: req.body.tags ? (typeof req.body.tags === 'string' ? req.body.tags.split(',').map((t: string) => t.trim()).filter((t: string) => t) : req.body.tags) : [],
      attachments,
      youtubeLinks,
      author: req.user._id,
      status: req.body.submitForReview === 'true' || req.body.submitForReview === true ? 'Pending' : 'Draft'
    });
    const createdArticle = await article.save();
    res.status(201).json(createdArticle);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error instanceof Error ? error.message : error });
  }
});

// Update article (Teacher/Student/Admin)
router.put('/:id', protect, async (req: AuthRequest, res) => {
  try {
    const article = await Article.findById(req.params.id);
    
    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    if (article.author.toString() !== req.user._id.toString() && req.user.role !== 'Admin') {
      return res.status(403).json({ message: 'Not authorized to edit this article' });
    }

    // Save current content as a version before updating
    if (req.body.content && req.body.content !== article.content) {
      article.versions.push({
        content: article.content,
        updatedAt: new Date(),
        updatedBy: req.user._id,
        versionNumber: article.versions.length + 1
      });
    }

    const updateData = { ...req.body };
    if (!updateData.topic) {
      delete updateData.topic;
    }

    // Apply updates
    Object.assign(article, {
      ...updateData,
      tags: req.body.tags ? (typeof req.body.tags === 'string' ? req.body.tags.split(',').map((t: string) => t.trim()).filter((t: string) => t) : req.body.tags) : article.tags,
      youtubeLinks: req.body.youtubeLinks ? JSON.parse(req.body.youtubeLinks) : article.youtubeLinks,
      status: req.body.submitForReview === 'true' || req.body.submitForReview === true ? 'Pending' : 'Draft'
    });

    const updatedArticle = await article.save();
    res.json(updatedArticle);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Delete article
router.delete('/:id', protect, async (req: AuthRequest, res) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    if (article.author.toString() !== req.user._id.toString() && req.user.role !== 'Admin') {
      return res.status(403).json({ message: 'Not authorized to delete this article' });
    }

    await article.deleteOne();
    
    await AuditLog.create({
      action: 'DELETE_ARTICLE',
      entityType: 'Article',
      entityId: req.params.id,
      user: req.user._id,
      details: `Deleted article: ${article.title}`,
      ipAddress: req.ip
    });

    res.json({ message: 'Article removed' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Approve article (Admin/Teacher only)
router.put('/:id/approve', protect, authorize('Admin', 'Teacher'), async (req, res) => {
  try {
    const article = await Article.findByIdAndUpdate(req.params.id, { status: 'Approved' }, { new: true });
    res.json(article);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Reject article (Admin/Teacher only)
router.put('/:id/reject', protect, authorize('Admin', 'Teacher'), async (req, res) => {
  try {
    const article = await Article.findByIdAndUpdate(req.params.id, { status: 'Rejected' }, { new: true });
    res.json(article);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

// Rate article
router.post('/:id/rate', protect, async (req: AuthRequest, res) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article) return res.status(404).json({ message: 'Article not found' });

    const { value } = req.body;
    if (value < 1 || value > 5) return res.status(400).json({ message: 'Invalid rating' });

    const userId = req.user._id;
    const existingRatingIndex = article.ratings.findIndex(r => r.user.toString() === userId.toString());

    if (existingRatingIndex >= 0) {
      article.ratings[existingRatingIndex].value = value;
    } else {
      article.ratings.push({ user: userId, value });
      article.ratingsCount += 1;
    }

    const totalRating = article.ratings.reduce((sum, r) => sum + r.value, 0);
    article.rating = totalRating / article.ratingsCount;

    await article.save();
    res.json(article);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
});

export default router;

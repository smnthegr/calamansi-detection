require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const multer = require('multer');
const Joi = require('joi');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');
const db = require('./db'); // Our SQLite database

const app = express();
const PORT = process.env.PORT || 3000;

// ============= TRACKING & LIMITS =============
const activeUploads = new Map();
const MAX_CONCURRENT_UPLOADS = 10;
const DAILY_API_LIMIT = parseInt(process.env.DAILY_API_LIMIT) || 5000;

// Circuit breaker for Roboflow API
let apiFailureCount = 0;
let circuitOpen = false;
let lastFailureTime = 0;

// ============= ENVIRONMENT CHECK =============
console.log('=== Environment Configuration ===');
console.log('NODE_ENV:', process.env.NODE_ENV || 'development');
console.log('PORT:', PORT);
console.log('ROBOFLOW_API_KEY:', process.env.ROBOFLOW_API_KEY ? '✓ Set' : '✗ NOT SET');
console.log('DAILY_API_LIMIT:', DAILY_API_LIMIT);
console.log('================================\n');

// ============= CLEANUP OLD RECORDS ON STARTUP =============
db.cleanOldRecords(90); // Keep 90 days of logs
db.backup(); // Create startup backup

// Log system health every 5 minutes
setInterval(() => {
  const memUsage = process.memoryUsage().heapUsed / 1024 / 1024;
  db.logHealth(memUsage, activeUploads.size, apiFailureCount);
}, 5 * 60 * 1000);

// ============= SECURITY HEADERS =============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// ============= CORS CONFIGURATION =============
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['http://localhost:3000'];

app.use(cors({
  origin: function(origin, callback) {
    // Block requests without origin in production
    if (!origin && process.env.NODE_ENV === 'production') {
      return callback(new Error('Origin required'));
    }
    
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

// ============= LOGGING =============
const logStream = fs.createWriteStream(
  path.join(__dirname, 'logs', 'access.log'), 
  { flags: 'a' }
);

if (!fs.existsSync(path.join(__dirname, 'logs'))) {
  fs.mkdirSync(path.join(__dirname, 'logs'));
}

morgan.token('sanitized-body', (req) => {
  if (req.body) {
    const sanitized = { ...req.body };
    delete sanitized.image;
    return JSON.stringify(sanitized);
  }
  return '';
});

app.use(morgan('combined', { stream: logStream }));
app.use(morgan('dev'));

// ============= RATE LIMITING =============
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: process.env.GLOBAL_RATE_LIMIT || 100,
  message: { error: 'Too many requests from all users. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.IP_RATE_LIMIT || 20,
  standardHeaders: true,
  legacyHeaders: false
});

const detectionLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: process.env.DETECTION_RATE_LIMIT || 10,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => req.ip
});

app.use(globalLimiter);

// ============= FILE UPLOAD CONFIGURATION =============
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and WebP are allowed.'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024,
    files: 1
  },
  fileFilter: fileFilter
});

// ============= INPUT VALIDATION SCHEMAS =============
const detectionSchema = Joi.object({
  confidence1: Joi.number().min(0).max(1).optional(),
  confidence2: Joi.number().min(0).max(1).optional()
});

// ============= MIDDLEWARE =============
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Serve static files with caching
app.use(express.static('public', {
  maxAge: '1d',
  etag: true
}));

// Request timeout middleware
app.use((req, res, next) => {
  req.setTimeout(30000);
  res.setTimeout(30000);
  next();
});

// ============= HELPER FUNCTIONS =============

async function optimizeImage(buffer, maxWidth = 1024) {
  try {
    const optimized = await sharp(buffer)
      .resize(maxWidth, maxWidth, {
        fit: 'inside',
        withoutEnlargement: true
      })
      .jpeg({ quality: 85, progressive: true })
      .toBuffer();
    
    return optimized;
  } catch (error) {
    console.warn('Image optimization failed, using original:', error.message);
    return buffer;
  }
}

async function callRoboflowAPI(modelUrl, base64Image, timeout = 20000) {
  // Check circuit breaker
  if (circuitOpen) {
    const timeSinceFailure = Date.now() - lastFailureTime;
    if (timeSinceFailure < 60000) { // 1 minute cooldown
      throw new Error('Service temporarily unavailable - too many failures');
    }
    // Try to close circuit
    circuitOpen = false;
    apiFailureCount = 0;
    console.log('🔄 Circuit breaker attempting to close...');
  }
  
  const apiKey = process.env.ROBOFLOW_API_KEY;
  
  if (!apiKey) {
    throw new Error('API key not configured');
  }

  if (!modelUrl) {
    throw new Error('Model URL not configured');
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await axios.post(
      `${modelUrl}?api_key=${apiKey}`,
      base64Image,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept-Encoding': 'gzip, deflate'
        },
        signal: controller.signal,
        timeout: timeout,
        validateStatus: function (status) {
          return status < 600;
        }
      }
    );

    clearTimeout(timeoutId);

    if (response.status !== 200) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(response.data)}`);
    }
    
    // Success - reset failure count
    apiFailureCount = 0;
    
    return response.data;
    
  } catch (error) {
    clearTimeout(timeoutId);
    
    // Track failures for circuit breaker
    apiFailureCount++;
    lastFailureTime = Date.now();
    
    if (apiFailureCount >= 5) {
      circuitOpen = true;
      console.error('🚨 Circuit breaker opened after 5 consecutive API failures');
    }
    
    if (error.code === 'ECONNABORTED' || error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    
    if (error.code === 'ENOTFOUND') {
      throw new Error('DNS lookup failed');
    }
    
    if (error.code === 'ECONNREFUSED') {
      throw new Error('Connection refused');
    }
    
    if (error.response) {
      const status = error.response.status;
      if (status === 429) throw new Error('API rate limit exceeded');
      if (status === 401 || status === 403) throw new Error('Authentication failed');
      if (status === 400) throw new Error('Invalid image data');
      throw new Error(`API request failed with status ${status}`);
    }
    
    throw new Error('Network error - ' + error.message);
  }
}

function sanitizeError(error) {
  const safeErrors = {
    'Request timeout': 'The request took too long. Please try again.',
    'API rate limit exceeded': 'Service limit reached. Please try again in a moment.',
    'Authentication failed': 'Service temporarily unavailable.',
    'Invalid image data': 'Invalid image format. Please try a different image.',
    'DNS lookup failed': 'Cannot reach detection service.',
    'Connection refused': 'Detection service not responding.',
    'API key not configured': 'Service configuration error.',
    'Model URL not configured': 'Service configuration error.',
    'Service temporarily unavailable - too many failures': 'Service temporarily unavailable. Please try again in a minute.'
  };

  for (const [key, value] of Object.entries(safeErrors)) {
    if (error.message.includes(key)) {
      return value;
    }
  }

  return 'An error occurred during processing.';
}

// ============= ROUTES =============

// Health check endpoint
app.get('/api/health', (req, res) => {
  const dbInfo = db.getDatabaseInfo();
  const apiUsage = db.getAPIUsageToday();
  
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    config: {
      hasApiKey: !!process.env.ROBOFLOW_API_KEY,
      hasModel1Url: !!process.env.MODEL_1_URL,
      hasModel2Url: !!process.env.MODEL_2_URL
    },
    system: {
      activeUploads: activeUploads.size,
      maxConcurrent: MAX_CONCURRENT_UPLOADS,
      circuitBreakerOpen: circuitOpen,
      apiFailures: apiFailureCount
    },
    database: dbInfo,
    apiUsage: {
      today: apiUsage.total_calls,
      limit: DAILY_API_LIMIT,
      remaining: DAILY_API_LIMIT - apiUsage.total_calls
    }
  });
});

// Stats endpoint (for admin dashboard)
app.get('/api/stats', (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    const stats = db.getStats(hours);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

// Main detection endpoint
app.post('/api/detect', 
  ipLimiter,
  detectionLimiter,
  upload.single('image'),
  async (req, res) => {
    const startTime = Date.now();
    const uploadId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    try {
      // CHECK 1: Concurrent upload limit
      if (activeUploads.size >= MAX_CONCURRENT_UPLOADS) {
        console.warn(`[${req.ip}] Rejected - server at capacity (${activeUploads.size}/${MAX_CONCURRENT_UPLOADS})`);
        return res.status(503).json({ 
          error: 'Server is busy processing other requests. Please try again in a moment.',
          type: 'capacity_error'
        });
      }
      
      activeUploads.set(uploadId, true);
      
      // CHECK 2: Daily API limit
      const apiUsage = db.getAPIUsageToday();
      if (apiUsage.total_calls >= DAILY_API_LIMIT) {
        console.error(`Daily API limit reached: ${apiUsage.total_calls}/${DAILY_API_LIMIT}`);
        return res.status(503).json({ 
          error: 'Daily service limit reached. Please try again tomorrow.',
          type: 'api_limit_error'
        });
      }
      
      // CHECK 3: Database rate limiting (more sophisticated than express-rate-limit)
      const rateLimitCheck = db.checkRateLimit(req.ip, 60, 20);
      if (!rateLimitCheck.allowed) {
        db.logDetection(req.ip, null, null, null, false, rateLimitCheck.reason, req.get('user-agent'));
        return res.status(429).json({ 
          error: rateLimitCheck.reason,
          type: 'rate_limit_error'
        });
      }
      
      // CHECK 4: File validation
      if (!req.file) {
        return res.status(400).json({ 
          error: 'No image file provided' 
        });
      }

      console.log(`\n[${uploadId}] Processing from ${req.ip}: ${req.file.originalname} (${(req.file.size / 1024).toFixed(2)} KB)`);

      // Validate request body
      const { error: validationError } = detectionSchema.validate(req.body);
      if (validationError) {
        return res.status(400).json({ 
          error: 'Invalid request parameters' 
        });
      }

      // Optimize image
      const optimizationStart = Date.now();
      const optimizedBuffer = await optimizeImage(req.file.buffer);
      const base64Image = optimizedBuffer.toString('base64');
      console.log(`[${uploadId}] Optimized in ${Date.now() - optimizationStart}ms (${(optimizedBuffer.length / 1024).toFixed(2)} KB)`);

      // Get model URLs
      const model1Url = process.env.MODEL_1_URL;
      const model2Url = process.env.MODEL_2_URL;

      if (!model1Url || !model2Url) {
        console.error('Model URLs not configured');
        return res.status(503).json({ 
          error: 'Service temporarily unavailable' 
        });
      }

      // Call both models in parallel
      console.log(`[${uploadId}] Calling both models in parallel...`);
      const apiCallStart = Date.now();
      
      const [model1Data, model2Data] = await Promise.all([
        callRoboflowAPI(model1Url, base64Image),
        callRoboflowAPI(model2Url, base64Image)
      ]);
      
      console.log(`[${uploadId}] API calls completed in ${Date.now() - apiCallStart}ms`);

      // Validate Model 1 results
      if (!model1Data.predictions || model1Data.predictions.length === 0) {
        db.logDetection(req.ip, null, null, Date.now() - startTime, false, 'No predictions from model 1', req.get('user-agent'));
        return res.status(400).json({ 
          error: 'Unable to analyze the image. Please try another image with better lighting.' 
        });
      }

      // Get top prediction from Model 1
      const topPrediction = model1Data.predictions.reduce((max, pred) => 
        pred.confidence > max.confidence ? pred : max
      , model1Data.predictions[0]);

      const predictedClass = topPrediction.class.toLowerCase();
      const confidence1 = topPrediction.confidence;

      // Validate calamansi detection
      const threshold1 = parseFloat(process.env.MODEL_1_THRESHOLD) || 0.50;
      const isNotCalamansi = predictedClass.includes('not') || 
                             predictedClass === 'not calamansi' || 
                             predictedClass === 'not-calamansi' ||
                             predictedClass === 'not_calamansi';

      if (isNotCalamansi && confidence1 > 0.70) {
        db.logDetection(req.ip, null, confidence1, Date.now() - startTime, false, 'Not calamansi detected', req.get('user-agent'));
        return res.status(400).json({
          error: `This does not appear to be a calamansi (${(confidence1 * 100).toFixed(2)}% confidence).`,
          type: 'validation_error'
        });
      }

      if (!isNotCalamansi && confidence1 < threshold1) {
        db.logDetection(req.ip, predictedClass, confidence1, Date.now() - startTime, false, 'Low confidence', req.get('user-agent'));
        return res.status(400).json({
          error: `Low confidence verification (${(confidence1 * 100).toFixed(2)}%). Please upload a clearer image.`,
          type: 'validation_error'
        });
      }

      // Validate Model 2 results
      if (!model2Data.predictions || model2Data.predictions.length === 0) {
        db.logDetection(req.ip, predictedClass, confidence1, Date.now() - startTime, false, 'No disease predictions', req.get('user-agent'));
        return res.status(400).json({ 
          error: 'No clear disease signs detected. Please ensure the affected area is visible.' 
        });
      }

      // Get top disease prediction
      const topDiseasePrediction = model2Data.predictions.reduce((max, pred) => 
        pred.confidence > max.confidence ? pred : max
      , model2Data.predictions[0]);

      const threshold2 = parseFloat(process.env.MODEL_2_THRESHOLD) || 0.50;
      
      if (topDiseasePrediction.confidence < threshold2) {
        db.logDetection(req.ip, topDiseasePrediction.class, topDiseasePrediction.confidence, Date.now() - startTime, false, 'Low disease confidence', req.get('user-agent'));
        return res.status(400).json({
          error: `Low confidence detection (${(topDiseasePrediction.confidence * 100).toFixed(2)}%). Please upload a clearer image.`,
          type: 'validation_error'
        });
      }

      // Prepare response
      const processingTime = Date.now() - startTime;
      const responseData = {
        model1: {
          class: predictedClass,
          confidence: parseFloat((confidence1 * 100).toFixed(2))
        },
        model2: {
          class: topDiseasePrediction.class.toLowerCase(),
          confidence: parseFloat((topDiseasePrediction.confidence * 100).toFixed(2)),
          boundingBox: {
            x: topDiseasePrediction.x,
            y: topDiseasePrediction.y,
            width: topDiseasePrediction.width,
            height: topDiseasePrediction.height
          }
        },
        imageData: `data:${req.file.mimetype};base64,${base64Image}`,
        imageWidth: model2Data.image.width,
        imageHeight: model2Data.image.height,
        allPredictions: model2Data.predictions.slice(0, 5).map(p => ({
          class: p.class,
          confidence: parseFloat((p.confidence * 100).toFixed(2)),
          x: p.x,
          y: p.y,
          width: p.width,
          height: p.height
        })),
        timestamp: new Date().toISOString(),
        processingTime
      };

      // Log successful detection
      db.logDetection(
        req.ip, 
        topDiseasePrediction.class, 
        topDiseasePrediction.confidence, 
        processingTime, 
        true, 
        null, 
        req.get('user-agent')
      );

      console.log(`[${uploadId}] ✓ Detection completed in ${processingTime}ms\n`);
      
      res.json(responseData);

    } catch (error) {
      console.error(`[${uploadId}] Detection error:`, error.message);
      
      // Log failed detection
      db.logDetection(
        req.ip, 
        null, 
        null, 
        Date.now() - startTime, 
        false, 
        error.message, 
        req.get('user-agent')
      );
      
      const sanitizedError = sanitizeError(error);
      res.status(500).json({ 
        error: sanitizedError,
        type: 'server_error'
      });
    } finally {
      // Always remove from active uploads
      activeUploads.delete(uploadId);
    }
  }
);

// ============= ERROR HANDLERS =============

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ 
      error: 'File size exceeds 10MB limit' 
    });
  }
  
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({ 
      error: 'Too many files uploaded' 
    });
  }
  
  if (err.message === 'Invalid file type. Only JPEG, PNG, and WebP are allowed.') {
    return res.status(400).json({ 
      error: err.message 
    });
  }

  res.status(500).json({ 
    error: 'An unexpected error occurred' 
  });
});

// ============= GRACEFUL SHUTDOWN =============
let server;

function gracefulShutdown(signal) {
  console.log(`\n${signal} received, closing server gracefully...`);
  
  // Stop accepting new connections
  server.close(() => {
    console.log('Server closed');
    
    // Create final backup
    db.backup();
    
    // Close database
    console.log('Database closed');
    
    process.exit(0);
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

// ============= SERVER START =============
if (process.env.NODE_ENV !== 'production') {
  server = app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`⚡ Features: Parallel API, Image optimization, SQLite tracking, Circuit breaker`);
    console.log(`💾 Database: ${db.getDatabaseInfo().path}\n`);
  });
} else {
  const https = require('https');
  
  if (!process.env.SSL_KEY_PATH || !process.env.SSL_CERT_PATH) {
    console.error('SSL certificates required in production');
    process.exit(1);
  }

  const httpsOptions = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH)
  };

  server = https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`🚀 Secure server running on https://localhost:${PORT}`);
    console.log(`📝 Environment: production`);
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
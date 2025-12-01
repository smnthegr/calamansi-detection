const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'usage.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = 10000');
db.pragma('temp_store = MEMORY');

// ============= SCHEMA SETUP =============

// Table 1: Detection logs
db.exec(`
  CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    disease TEXT,
    confidence REAL,
    processing_time INTEGER,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Table 2: API usage tracking (for cost monitoring)
db.exec(`
  CREATE TABLE IF NOT EXISTS api_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    model_1_calls INTEGER DEFAULT 0,
    model_2_calls INTEGER DEFAULT 0,
    total_calls INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(date)
  )
`);

// Table 3: Rate limit tracking (for abuse prevention)
db.exec(`
  CREATE TABLE IF NOT EXISTS rate_limits (
    ip TEXT PRIMARY KEY,
    request_count INTEGER DEFAULT 0,
    first_request INTEGER NOT NULL,
    last_request INTEGER NOT NULL,
    blocked BOOLEAN DEFAULT 0
  )
`);

// Table 4: System health logs
db.exec(`
  CREATE TABLE IF NOT EXISTS health_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    memory_usage REAL,
    active_connections INTEGER,
    error_count INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// ============= INDEXES FOR PERFORMANCE =============
db.exec(`CREATE INDEX IF NOT EXISTS idx_detections_ip_timestamp ON detections(ip, timestamp)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_detections_success ON detections(success)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_api_calls_date ON api_calls(date)`);

console.log('✓ Database initialized at:', dbPath);

// ============= PREPARED STATEMENTS (for performance) =============

const statements = {
  // Detection logging
  insertDetection: db.prepare(`
    INSERT INTO detections (ip, timestamp, disease, confidence, processing_time, success, error_message, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `),
  
  // API call tracking
  incrementAPICalls: db.prepare(`
    INSERT INTO api_calls (date, model_1_calls, model_2_calls, total_calls)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(date) DO UPDATE SET
      model_1_calls = model_1_calls + excluded.model_1_calls,
      model_2_calls = model_2_calls + excluded.model_2_calls,
      total_calls = total_calls + excluded.total_calls
  `),
  
  // Rate limiting
  getRecentDetections: db.prepare(`
    SELECT COUNT(*) as count 
    FROM detections 
    WHERE ip = ? AND timestamp > ? AND success = 1
  `),
  
  updateRateLimit: db.prepare(`
    INSERT INTO rate_limits (ip, request_count, first_request, last_request, blocked)
    VALUES (?, 1, ?, ?, 0)
    ON CONFLICT(ip) DO UPDATE SET
      request_count = request_count + 1,
      last_request = excluded.last_request
  `),
  
  getRateLimit: db.prepare(`
    SELECT * FROM rate_limits WHERE ip = ?
  `),
  
  blockIP: db.prepare(`
    UPDATE rate_limits SET blocked = 1 WHERE ip = ?
  `),
  
  // Health monitoring
  insertHealthLog: db.prepare(`
    INSERT INTO health_logs (timestamp, memory_usage, active_connections, error_count)
    VALUES (?, ?, ?, ?)
  `),
  
  // Analytics queries
  getTodayStats: db.prepare(`
    SELECT 
      COUNT(*) as total_detections,
      SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
      SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
      AVG(CASE WHEN success = 1 THEN processing_time END) as avg_processing_time,
      COUNT(DISTINCT ip) as unique_users
    FROM detections
    WHERE timestamp > ?
  `),
  
  getTopDiseases: db.prepare(`
    SELECT disease, COUNT(*) as count
    FROM detections
    WHERE success = 1 AND timestamp > ?
    GROUP BY disease
    ORDER BY count DESC
    LIMIT 10
  `),
  
  getRecentErrors: db.prepare(`
    SELECT timestamp, ip, error_message, created_at
    FROM detections
    WHERE success = 0
    ORDER BY timestamp DESC
    LIMIT 50
  `)
};

// ============= PUBLIC API FUNCTIONS =============

/**
 * Log a detection attempt
 */
function logDetection(ip, disease, confidence, processingTime, success, errorMessage = null, userAgent = null) {
  try {
    statements.insertDetection.run(
      ip,
      Date.now(),
      disease,
      confidence,
      processingTime,
      success ? 1 : 0,
      errorMessage,
      userAgent
    );
    
    // Track API usage
    if (success) {
      const today = new Date().toISOString().split('T')[0];
      statements.incrementAPICalls.run(today, 1, 1, 2); // 2 API calls per detection (model 1 + model 2)
    }
  } catch (error) {
    console.error('Failed to log detection:', error.message);
  }
}

/**
 * Check if IP has exceeded rate limits
 */
function checkRateLimit(ip, windowMinutes = 60, maxRequests = 20) {
  try {
    const cutoff = Date.now() - (windowMinutes * 60 * 1000);
    const result = statements.getRecentDetections.get(ip, cutoff);
    
    // Update rate limit tracking
    statements.updateRateLimit.run(ip, Date.now(), Date.now());
    
    // Check if IP is blocked
    const rateLimit = statements.getRateLimit.get(ip);
    if (rateLimit && rateLimit.blocked) {
      return { allowed: false, reason: 'IP blocked due to abuse' };
    }
    
    const count = result.count;
    
    if (count >= maxRequests) {
      // Auto-block if severely over limit
      if (count >= maxRequests * 2) {
        statements.blockIP.run(ip);
        console.warn(`🚨 IP blocked for abuse: ${ip} (${count} requests)`);
        return { allowed: false, reason: 'IP blocked due to excessive requests' };
      }
      
      return { allowed: false, reason: 'Rate limit exceeded', count };
    }
    
    return { allowed: true, count, remaining: maxRequests - count };
  } catch (error) {
    console.error('Rate limit check failed:', error.message);
    return { allowed: true }; // Fail open to not break the service
  }
}

/**
 * Get today's API usage for cost monitoring
 */
function getAPIUsageToday() {
  try {
    const today = new Date().toISOString().split('T')[0];
    const result = db.prepare(`
      SELECT * FROM api_calls WHERE date = ?
    `).get(today);
    
    return result || { model_1_calls: 0, model_2_calls: 0, total_calls: 0 };
  } catch (error) {
    console.error('Failed to get API usage:', error.message);
    return { model_1_calls: 0, model_2_calls: 0, total_calls: 0 };
  }
}

/**
 * Get statistics for dashboard/monitoring
 */
function getStats(hours = 24) {
  try {
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    
    const summary = statements.getTodayStats.get(cutoff);
    const topDiseases = statements.getTopDiseases.all(cutoff);
    const recentErrors = statements.getRecentErrors.all();
    const apiUsage = getAPIUsageToday();
    
    return {
      summary: summary || {},
      topDiseases: topDiseases || [],
      recentErrors: recentErrors || [],
      apiUsage
    };
  } catch (error) {
    console.error('Failed to get stats:', error.message);
    return null;
  }
}

/**
 * Log system health metrics
 */
function logHealth(memoryUsage, activeConnections, errorCount) {
  try {
    statements.insertHealthLog.run(
      Date.now(),
      memoryUsage,
      activeConnections,
      errorCount
    );
  } catch (error) {
    console.error('Failed to log health:', error.message);
  }
}

/**
 * Clean old records (run daily via cron or at startup)
 */
function cleanOldRecords(daysToKeep = 90) {
  try {
    const cutoff = Date.now() - (daysToKeep * 24 * 60 * 60 * 1000);
    
    const deleted = db.prepare(`
      DELETE FROM detections WHERE timestamp < ?
    `).run(cutoff);
    
    const deletedHealth = db.prepare(`
      DELETE FROM health_logs WHERE timestamp < ?
    `).run(cutoff);
    
    console.log(`🧹 Cleaned ${deleted.changes} old detection records and ${deletedHealth.changes} health logs`);
    
    // Vacuum to reclaim space
    db.pragma('vacuum');
    
    return { deleted: deleted.changes, deletedHealth: deletedHealth.changes };
  } catch (error) {
    console.error('Failed to clean old records:', error.message);
    return { deleted: 0, deletedHealth: 0 };
  }
}

/**
 * Backup database
 */
function backup() {
  try {
    const backupDir = path.join(__dirname, 'backups');
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(backupDir, `backup-${timestamp}.db`);
    
    db.backup(backupPath);
    
    console.log(`✓ Database backed up to: ${backupPath}`);
    
    // Keep only last 7 backups
    const backups = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('backup-'))
      .sort()
      .reverse();
    
    if (backups.length > 7) {
      backups.slice(7).forEach(old => {
        fs.unlinkSync(path.join(backupDir, old));
      });
    }
    
    return backupPath;
  } catch (error) {
    console.error('Backup failed:', error.message);
    return null;
  }
}

/**
 * Get database statistics
 */
function getDatabaseInfo() {
  try {
    const stats = {
      size: fs.statSync(dbPath).size,
      path: dbPath,
      tables: {}
    };
    
    // Count records in each table
    const tables = ['detections', 'api_calls', 'rate_limits', 'health_logs'];
    tables.forEach(table => {
      const count = db.prepare(`SELECT COUNT(*) as count FROM ${table}`).get();
      stats.tables[table] = count.count;
    });
    
    return stats;
  } catch (error) {
    console.error('Failed to get database info:', error.message);
    return null;
  }
}

// ============= GRACEFUL SHUTDOWN =============
process.on('exit', () => {
  db.close();
});

process.on('SIGINT', () => {
  console.log('\nClosing database...');
  db.close();
  process.exit(0);
});

// ============= EXPORTS =============
module.exports = {
  db, // Export raw db for advanced queries if needed
  logDetection,
  checkRateLimit,
  getAPIUsageToday,
  getStats,
  logHealth,
  cleanOldRecords,
  backup,
  getDatabaseInfo
};
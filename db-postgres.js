const { sql } = require('@vercel/postgres');

// Initialize database tables
async function initializeDatabase() {
  try {
    // Create detections table
    await sql`
      CREATE TABLE IF NOT EXISTS detections (
        id SERIAL PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL,
        disease VARCHAR(100),
        confidence DECIMAL(5,4),
        processing_time INTEGER,
        success BOOLEAN NOT NULL,
        error_reason TEXT,
        user_agent TEXT,
        timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )
    `;

    // Create health logs table
    await sql`
      CREATE TABLE IF NOT EXISTS health_logs (
        id SERIAL PRIMARY KEY,
        memory_usage DECIMAL(10,2),
        active_uploads INTEGER,
        api_failures INTEGER,
        timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )
    `;

    // Create indexes for better performance
    await sql`
      CREATE INDEX IF NOT EXISTS idx_detections_timestamp 
      ON detections(timestamp)
    `;

    await sql`
      CREATE INDEX IF NOT EXISTS idx_detections_ip 
      ON detections(ip_address, timestamp)
    `;

    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

// Log a detection
async function logDetection(ipAddress, disease, confidence, processingTime, success, errorReason, userAgent) {
  try {
    await sql`
      INSERT INTO detections (
        ip_address, disease, confidence, processing_time, 
        success, error_reason, user_agent
      ) VALUES (
        ${ipAddress}, ${disease}, ${confidence}, ${processingTime}, 
        ${success}, ${errorReason}, ${userAgent}
      )
    `;
  } catch (error) {
    console.error('Failed to log detection:', error);
  }
}

// Log health metrics
async function logHealth(memoryUsage, activeUploads, apiFailures) {
  try {
    await sql`
      INSERT INTO health_logs (memory_usage, active_uploads, api_failures)
      VALUES (${memoryUsage}, ${activeUploads}, ${apiFailures})
    `;
  } catch (error) {
    console.error('Failed to log health:', error);
  }
}

// Get API usage for today
async function getAPIUsageToday() {
  try {
    const result = await sql`
      SELECT COUNT(*) as total_calls
      FROM detections
      WHERE timestamp >= CURRENT_DATE
      AND success = true
    `;
    
    return {
      total_calls: parseInt(result.rows[0]?.total_calls || 0)
    };
  } catch (error) {
    console.error('Failed to get API usage:', error);
    return { total_calls: 0 };
  }
}

// Check rate limit for an IP
async function checkRateLimit(ipAddress, windowSeconds, maxRequests) {
  try {
    const result = await sql`
      SELECT COUNT(*) as request_count
      FROM detections
      WHERE ip_address = ${ipAddress}
      AND timestamp > NOW() - INTERVAL '${windowSeconds} seconds'
    `;

    const count = parseInt(result.rows[0]?.request_count || 0);

    if (count >= maxRequests) {
      return {
        allowed: false,
        reason: `Rate limit exceeded. Maximum ${maxRequests} requests per ${windowSeconds} seconds.`
      };
    }

    return { allowed: true };
  } catch (error) {
    console.error('Rate limit check failed:', error);
    return { allowed: true }; // Fail open
  }
}

// Get database info
async function getDatabaseInfo() {
  try {
    const result = await sql`
      SELECT 
        (SELECT COUNT(*) FROM detections) as total_detections,
        (SELECT COUNT(*) FROM health_logs) as total_health_logs
    `;

    return {
      type: 'postgres',
      total_detections: parseInt(result.rows[0]?.total_detections || 0),
      total_health_logs: parseInt(result.rows[0]?.total_health_logs || 0)
    };
  } catch (error) {
    console.error('Failed to get database info:', error);
    return {
      type: 'postgres',
      total_detections: 0,
      total_health_logs: 0
    };
  }
}

// Get statistics
async function getStats(hours = 24) {
  try {
    const result = await sql`
      SELECT 
        COUNT(*) as total_requests,
        COUNT(*) FILTER (WHERE success = true) as successful,
        COUNT(*) FILTER (WHERE success = false) as failed,
        AVG(processing_time) FILTER (WHERE success = true) as avg_processing_time,
        COUNT(DISTINCT ip_address) as unique_ips
      FROM detections
      WHERE timestamp > NOW() - INTERVAL '${hours} hours'
    `;

    const diseaseStats = await sql`
      SELECT disease, COUNT(*) as count
      FROM detections
      WHERE success = true
      AND timestamp > NOW() - INTERVAL '${hours} hours'
      AND disease IS NOT NULL
      GROUP BY disease
      ORDER BY count DESC
      LIMIT 10
    `;

    return {
      period_hours: hours,
      total_requests: parseInt(result.rows[0]?.total_requests || 0),
      successful: parseInt(result.rows[0]?.successful || 0),
      failed: parseInt(result.rows[0]?.failed || 0),
      avg_processing_time: parseFloat(result.rows[0]?.avg_processing_time || 0).toFixed(2),
      unique_ips: parseInt(result.rows[0]?.unique_ips || 0),
      disease_distribution: diseaseStats.rows.map(row => ({
        disease: row.disease,
        count: parseInt(row.count)
      }))
    };
  } catch (error) {
    console.error('Failed to get stats:', error);
    return {
      period_hours: hours,
      total_requests: 0,
      successful: 0,
      failed: 0,
      avg_processing_time: '0.00',
      unique_ips: 0,
      disease_distribution: []
    };
  }
}

// Clean old records (for maintenance)
async function cleanOldRecords(daysToKeep = 90) {
  try {
    await sql`
      DELETE FROM detections
      WHERE timestamp < NOW() - INTERVAL '${daysToKeep} days'
    `;

    await sql`
      DELETE FROM health_logs
      WHERE timestamp < NOW() - INTERVAL '${daysToKeep} days'
    `;

    console.log(`✅ Cleaned records older than ${daysToKeep} days`);
  } catch (error) {
    console.error('Failed to clean old records:', error);
  }
}

// Backup function (not needed for Postgres, but keeping for compatibility)
function backup() {
  console.log('Backup not needed for Vercel Postgres (automatically managed)');
}

module.exports = {
  initializeDatabase,
  logDetection,
  logHealth,
  getAPIUsageToday,
  checkRateLimit,
  getDatabaseInfo,
  getStats,
  cleanOldRecords,
  backup
};
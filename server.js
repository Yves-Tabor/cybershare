import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 3001;

// Session storage (in production, use Redis or database)
const sessions = new Map();
const SCAN_SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

// Legal compliance logging
async function logLegalActivity(activity, data) {
  try {
    const logEntry = {
      timestamp: new Date().toISOString(),
      activity: activity, // 'legal_acceptance', 'scan_initiated', 'scan_completed'
      sessionId: data.sessionId,
      userEmail: data.userEmail,
      username: data.username,
      targetUrl: data.targetUrl,
      ip: data.ip || 'unknown',
      userAgent: data.userAgent,
      legalTermsAccepted: data.legalTermsAccepted,
      legalTermsVersion: data.legalTermsVersion,
      scanResults: data.scanResults || null
    };

    const logFile = path.join(__dirname, 'legal-compliance.log');
    await fs.promises.appendFile(logFile, JSON.stringify(logEntry) + '\n');
    console.log(`Legal activity logged: ${activity} for session ${data.sessionId}`);
  } catch (error) {
    console.error('Failed to log legal activity:', error);
  }
}

// Security middleware
app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // Remove server signature
  res.removeHeader('X-Powered-By');
  
  next();
});

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Session management middleware
const sessionMiddleware = (req, res, next) => {
  const sessionId = req.headers['x-session-id'] || req.ip;
  
  // Clean up expired sessions
  for (const [id, session] of sessions.entries()) {
    if (Date.now() - session.lastActivity > SCAN_SESSION_TIMEOUT) {
      sessions.delete(id);
    }
  }
  
  // Get or create session
  let session = sessions.get(sessionId);
  if (!session) {
    session = {
      id: sessionId,
      scans: [],
      lastActivity: Date.now(),
      scanCount: 0,
      createdAt: Date.now()
    };
    sessions.set(sessionId, session);
  }
  
  // Update last activity
  session.lastActivity = Date.now();
  req.session = session;
  
  next();
};

// Rate limiting per session
const sessionRateLimit = (req, res, next) => {
  const session = req.session;
  const oneHour = 60 * 60 * 1000;
  
  // Reset scan count if more than an hour has passed
  if (Date.now() - session.createdAt > oneHour) {
    session.scanCount = 0;
    session.createdAt = Date.now();
  }
  
  // Limit scans per session
  if (session.scanCount >= 20) {
    return res.status(429).json({
      success: false,
      error: 'Scan limit exceeded. Please try again later.',
      retryAfter: Math.ceil((oneHour - (Date.now() - session.createdAt)) / 1000)
    });
  }
  
  session.scanCount++;
  next();
};

// Input validation middleware
const validateUrl = (req, res, next) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ 
      success: false, 
      error: 'URL is required' 
    });
  }

  // Basic URL format validation
  const urlPattern = /^https?:\/\/.+/;
  if (!urlPattern.test(url)) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid URL format. URL must start with http:// or https://' 
    });
  }

  // Prevent localhost and private IP ranges
  const forbiddenPatterns = [
    /localhost/i,
    /127\.0\.0\.1/,
    /192\.168\./,
    /10\./,
    /172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /169\.254\./,
    /::1/,
    /file:\/\//
  ];

  for (const pattern of forbiddenPatterns) {
    if (pattern.test(url)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Scanning localhost, private IPs, or local files is not allowed for security reasons' 
      });
    }
  }

  // URL length validation
  if (url.length > 2048) {
    return res.status(400).json({ 
      success: false, 
      error: 'URL is too long (maximum 2048 characters)' 
    });
  }

  // Prevent potentially dangerous URLs
  const dangerousPatterns = [
    /javascript:/i,
    /data:/i,
    /vbscript:/i,
    /<script/i,
    /onload=/i,
    /onerror=/i
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(url)) {
      return res.status(400).json({ 
        success: false, 
        error: 'URL contains potentially dangerous content' 
      });
    }
  }

  next();
};

const validateScanData = (req, res, next) => {
  const { results, url, timestamp } = req.body;
  
  if (!results || !Array.isArray(results)) {
    return res.status(400).json({ 
      error: 'Invalid scan results data' 
    });
  }

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ 
      error: 'URL is required for report generation' 
    });
  }

  if (!timestamp || typeof timestamp !== 'string') {
    return res.status(400).json({ 
      error: 'Timestamp is required for report generation' 
    });
  }

  // Validate results structure
  for (const result of results) {
    if (!result.title || !result.status || !result.recommendation) {
      return res.status(400).json({ 
        error: 'Invalid scan result format' 
      });
    }
  }

  next();
};

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10 // limit each IP to 10 requests per windowMs
});
app.use('/api/scan', limiter);

// Security Headers Scanner
async function scanHeaders(url) {
  try {
    const res = await fetch(url, { 
      method: 'GET',
      timeout: 10000,
      headers: {
        'User-Agent': 'CyberShare-Scanner/1.0'
      }
    });
    
    const headers = res.headers.raw();
    const requiredHeaders = [
      'content-security-policy',
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'x-xss-protection',
      'permissions-policy'
    ];

    const missing = requiredHeaders.filter(h => !headers[h.toLowerCase()]);
    const present = requiredHeaders.filter(h => headers[h.toLowerCase()]);

    if (missing.length > 0) {
      const explanations = {
        'content-security-policy': 'Prevents hackers from injecting malicious code into your website',
        'strict-transport-security': 'Forces secure HTTPS connections and protects against eavesdropping',
        'x-frame-options': 'Stops attackers from embedding your site in malicious iframes (clickjacking)',
        'x-content-type-options': 'Prevents browsers from misinterpreting file types (MIME-sniffing attacks)',
        'referrer-policy': 'Controls how much referrer user information is sent to other websites when they are crossing',
        'x-xss-protection': 'Enables browser built-in protection against cross-site scripting attacks',
        'permissions-policy': 'Controls access to browser features like camera and microphone'
      };

      const detailedMissing = missing.map(header => ({
        header: header,
        whyItMatters: explanations[header] || 'Important security protection',
        riskLevel: header.includes('content-security-policy') || header.includes('strict-transport-security') ? 'HIGH' : 'MEDIUM'
      }));

      return {
        title: 'SECURITY HEADERS',
        status: 'FAIL',
        recommendation: `Missing ${missing.length} important security protections. These headers help defend against common hacker attacks.`,
        details: {
          present: present,
          missing: detailedMissing,
          totalHeaders: Object.keys(headers).length,
          explanation: 'Security headers are like security guards for your website - they tell browsers how to protect your visitors from attacks.',
          riskAssessment: missing.length > 4 ? 'HIGH RISK: Multiple critical protections missing' : 'MEDIUM RISK: Some protections missing'
        }
      };
    } else {
      return {
        title: 'SECURITY HEADERS',
        status: 'PASS',
        recommendation: 'All recommended security headers are present. This is a good sign that your website is taking proactive steps to protect against common web attacks.',
        details: {
          present: present,
          totalHeaders: Object.keys(headers).length,
          explanation: 'Security headers are like security guards for your website - they tell browsers how to protect your visitors from attacks.',
          securityGrade: 'A',
          securityScore: 100
        }
      };
    }
  } catch (err) {
    return {
      title: 'SECURITY HEADERS',
      status: 'ERROR',
      recommendation: `Unable to fetch headers: ${err.message}`,
      error: err.message
    };
  }
}

// SSL/TLS Scanner
async function scanSSL(url) {
  try {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    
    if (!isHttps) {
      return {
        title: 'SSL/TLS',
        status: 'FAIL',
        recommendation: 'Site does not use HTTPS. Enable SSL/TLS encryption.',
        details: { protocol: parsedUrl.protocol }
      };
    }

    // Basic HTTPS check
    const res = await fetch(url, { 
      method: 'GET',
      timeout: 10000 
    });

    return {
      title: 'SSL/TLS ENCRYPTION',
      status: 'PASS',
      recommendation: 'Great! Your website uses HTTPS encryption, which protects user data from hackers. Always add HSTS (HTTP Strict Transport Security) for extra protection.',
      details: {
        protocol: 'https',
        certificate: 'Valid (basic check passed)',
        explanation: 'HTTPS is like sending your website data in a locked, armored truck instead of a postcard - hackers can\'t read it.',
        whatThisProtects: 'Passwords, credit card numbers, personal information, and login sessions from being stolen',
        riskWithoutIt: 'Without HTTPS, hackers can steal all user data and even modify your website content'
      }
    };
  } catch (err) {
    return {
      title: 'SSL/TLS ENCRYPTION',
      status: 'ERROR',
      recommendation: `Unable to check encryption: ${err.message}`,
      error: err.message,
      explanation: 'HTTPS encryption check failed - this could mean your website doesn\'t use secure connections.'
    };
  }
}

// Port Scanner (basic common ports)
async function scanPorts(url) {
  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;
    
    // Note: Actual port scanning requires more advanced networking
    // This is a simplified check for common web ports
    const commonPorts = [80, 443, 8080, 8443];
    const results = [];

    for (const port of commonPorts) {
      try {
        const testUrl = `${parsedUrl.protocol}//${hostname}:${port}`;
        const res = await fetch(testUrl, { 
          method: 'HEAD',
          timeout: 5000 
        });
        
        if (res.status < 500) {
          results.push({ port, status: 'open', service: res.status });
        }
      } catch (e) {
        // Port is closed or filtered
      }
    }

    return {
      title: 'OPEN PORTS',
      status: 'INFO',
      recommendation: 'Found open ports that could be potential entry points for hackers. Make sure only necessary ports are open.',
      details: { 
        openPorts: results,
        note: 'Limited scan of common web ports only',
        explanation: 'Ports are like doors to your website - the more doors you have open, the more chances hackers have to break in.',
        whatThisMeans: 'Each open port is a potential entry point that attackers could try to exploit',
        securityTip: 'Only keep ports open that you absolutely need for your website to function'
      }
    };
  } catch (err) {
    return {
      title: 'PORT DETECTION',
      status: 'ERROR',
      recommendation: `Port scan failed: ${err.message}`,
      error: err.message
    };
  }
}

// API Security Assessment Scanner
async function assessAPISecurity(url) {
  try {
    const results = {
      title: 'API SECURITY ASSESSMENT',
      status: 'PASS',
      recommendation: 'API endpoints appear to be properly secured.',
      details: {}
    };


    const commonEndpoints = [
      '/api/v1/users',
      '/api/users',
      '/api/data',
      '/api/admin',
      '/graphql',
      '/rest/api',
      '/api/auth',
      '/api/token'
    ];

    const baseUrl = new URL(url).origin;
    let exposedEndpoints = [];
    let securityIssues = [];

    // Test common API endpoints
    for (const endpoint of commonEndpoints) {
      try {
        const testUrl = baseUrl + endpoint;
        const response = await fetch(testUrl, {
          method: 'GET',
          timeout: 5000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
          }
        });

        if (response.status !== 404) {
          exposedEndpoints.push({
            endpoint: endpoint,
            status: response.status,
            accessible: response.status < 500
          });

          // Check for security issues
          if (response.status === 200) {
            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('json')) {
              securityIssues.push(`Unauthenticated data access at ${endpoint}`);
            }
          }

          if (response.status === 401 || response.status === 403) {
            results.details.authRequired = (results.details.authRequired || 0) + 1;
          }
        }
      } catch (error) {
        // Endpoint doesn't exist or network error - this is expected
      }
    }

    // Test for API documentation exposure
    const docEndpoints = ['/swagger', '/api/docs', '/api/documentation', '/redoc'];
    for (const doc of docEndpoints) {
      try {
        const docUrl = baseUrl + doc;
        const response = await fetch(docUrl, { timeout: 3000 });
        if (response.status === 200) {
          securityIssues.push(`API documentation exposed at ${doc}`);
        }
      } catch (error) {
        // Expected for non-existent endpoints
      }
    }

    // Test for GraphQL endpoint security
    try {
      const graphqlUrl = baseUrl + '/graphql';
      const graphqlQuery = {
        query: '{ __schema { types { name } } }'
      };

      const response = await fetch(graphqlUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(graphqlQuery),
        timeout: 5000
      });

      if (response.status === 200) {
        const data = await response.json();
        if (data.data && data.data.__schema) {
          securityIssues.push('GraphQL introspection enabled - schema exposed');
        }
      }
    } catch (error) {
      // GraphQL endpoint doesn't exist or is secured
    }

    // Test for API versioning
    const versionEndpoints = ['/api/v1/', '/api/v2/', '/api/v3/'];
    let hasVersioning = false;
    for (const version of versionEndpoints) {
      try {
        const versionUrl = baseUrl + version;
        const response = await fetch(versionUrl, { 
          method: 'OPTIONS',
          timeout: 3000 
        });
        if (response.status !== 404) {
          hasVersioning = true;
          break;
        }
      } catch (error) {
        // Expected
      }
    }

    // Compile results
    results.details.exposedEndpoints = exposedEndpoints.length;
    results.details.securityIssues = securityIssues.length;
    results.details.hasVersioning = hasVersioning;
    results.details.issues = securityIssues;

    if (securityIssues.length > 0) {
      results.status = 'WARN';
      results.recommendation = `Found ${securityIssues.length} API security weaknesses that hackers could exploit to steal data or break into your systems.`;
    }

    if (exposedEndpoints.length > 5) {
      results.status = 'FAIL';
      results.recommendation = `Too many exposed API endpoints (${exposedEndpoints.length})! This greatly increases your attack surface - hackers have many more ways to break in.`;
    }

    // Add explanations
    results.details.explanation = 'APIs are like messengers that carry data between different parts of your website. Unprotected APIs are like leaving your doors unlocked - anyone can walk in and take your data.';
    results.details.whatThisProtects = 'User accounts, personal data, payment information, and internal systems from unauthorized access';
    results.details.realWorldRisk = 'Hackers can steal user data, take over accounts, or even shut down your entire website through vulnerable APIs';

    return results;

  } catch (err) {
    return {
      title: 'API SECURITY ASSESSMENT',
      status: 'ERROR',
      recommendation: `API security assessment failed: ${err.message}`,
      error: err.message
    };
  }
}

// Information Disclosure Assessment Scanner
async function assessInfoDisclosure(url) {
  try {
    const results = {
      title: 'INFORMATION DISCLOSURE',
      status: 'PASS',
      recommendation: 'No sensitive information disclosure detected.',
      details: {}
    };

    const disclosures = [];
    const sensitivePatterns = [
      // Error messages
      /error|exception|stack trace|fatal error/i,
      // Database errors
      /sql|mysql|postgresql|mongodb|database error/i,
      // Server info
      /apache|nginx|iis|server version|php version/i,
      // Framework info
      /django|flask|express|spring|laravel|rails/i,
      // Debug info
      /debug|development|staging|test mode/i,
      // File paths
      /\/var\/www|\/home\/|c:\\|file:\/\/|\/etc\//i,
      // API keys (basic pattern)
      /api[_-]?key|secret[_-]?key|access[_-]?token/i
    ];

    try {
      // Test main page
      const response = await fetch(url, {
        method: 'GET',
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        }
      });

      const content = await response.text();
      
      // Check for sensitive information in response content
      for (const pattern of sensitivePatterns) {
        const matches = content.match(pattern);
        if (matches) {
          disclosures.push(`Sensitive pattern detected: ${matches[0]}`);
        }
      }

      // Check response headers for information disclosure
      const headers = response.headers;
      const sensitiveHeaders = [
        'server',
        'x-powered-by',
        'x-aspnet-version',
        'x-generator',
        'x-drupal-cache'
      ];

      for (const header of sensitiveHeaders) {
        const value = headers.get(header);
        if (value) {
          disclosures.push(`Information disclosure in header: ${header}: ${value}`);
        }
      }

      // Test for common disclosure paths
      const disclosurePaths = [
        '/robots.txt',
        '/sitemap.xml',
        '/.env',
        '/config.php',
        '/web.config',
        '/.git/config',
        '/phpinfo.php',
        '/test.php',
        '/info.php'
      ];

      const baseUrl = new URL(url).origin;
      let exposedFiles = [];

      for (const path of disclosurePaths) {
        try {
          const testUrl = baseUrl + path;
          const fileResponse = await fetch(testUrl, {
            method: 'GET',
            timeout: 5000
          });

          if (fileResponse.status === 200) {
            const fileContent = await fileResponse.text();
            if (fileContent.length > 0 && fileContent.length < 100000) { // Reasonable file size
              exposedFiles.push({
                path: path,
                size: fileContent.length,
                accessible: true
              });

              // Check file content for sensitive info
              for (const pattern of sensitivePatterns) {
                const matches = fileContent.match(pattern);
                if (matches) {
                  disclosures.push(`Sensitive info in ${path}: ${matches[0]}`);
                }
              }
            }
          }
        } catch (error) {
          // File doesn't exist or access denied - this is good
        }
      }

      // Test error pages for information disclosure
      try {
        const errorUrl = baseUrl + '/nonexistent-page-404-test-' + Date.now();
        const errorResponse = await fetch(errorUrl, {
          method: 'GET',
          timeout: 5000
        });

        const errorContent = await errorResponse.text();
        for (const pattern of sensitivePatterns) {
          const matches = errorContent.match(pattern);
          if (matches) {
            disclosures.push(`Error page disclosure: ${matches[0]}`);
          }
        }
      } catch (error) {
        // Expected for 404 errors
      }

      // Compile results
      results.details.disclosures = disclosures.length;
      results.details.exposedFiles = exposedFiles.length;
      results.details.issues = disclosures;
      results.details.exposedFilesList = exposedFiles;

      if (disclosures.length > 0) {
        results.status = 'WARN';
        results.recommendation = `Found ${disclosures.length} information leaks that give hackers clues about how to attack your website.`;
      }

      if (disclosures.length > 5 || exposedFiles.length > 2) {
        results.status = 'FAIL';
        results.recommendation = `CRITICAL: Found ${disclosures.length} serious information leaks! Hackers can use this information to plan attacks against your website.`;
      }

      // Add explanations
      results.details.explanation = 'Information disclosure is like accidentally leaving your house keys and alarm codes in plain sight - it gives attackers everything they need to break in.';
      results.details.whatHackersLearn = 'Server software versions, file locations, error messages that reveal system weaknesses, and configuration details';
      results.details.realDanger = 'Hackers use these clues to find specific vulnerabilities and craft targeted attacks against your website';
      results.details.analogy = 'This is like a burglar finding your security system manual - they know exactly how to bypass your protections';

      return results;

    } catch (error) {
      disclosures.push(`Failed to analyze content: ${error.message}`);
    }

    return results;

  } catch (err) {
    return {
      title: 'INFORMATION DISCLOSURE',
      status: 'ERROR',
      recommendation: `Information disclosure assessment failed: ${err.message}`,
      error: err.message
    };
  }
}

// Technology Detection Scanner
async function detectTech(url) {
  try {
    const res = await fetch(url, { 
      method: 'GET',
      timeout: 10000 
    });
    
    const html = await res.text();
    const headers = res.headers.raw();
    
    const detections = [];
    
    // Check for common technologies
    if (headers['server']) {
      detections.push(`Server: ${headers['server'][0]}`);
    }
    
    if (headers['x-powered-by']) {
      detections.push(`Powered By: ${headers['x-powered-by'][0]}`);
    }
    
    // Check for common frameworks in HTML
    if (html.includes('react') || html.includes('React')) {
      detections.push('React.js detected');
    }
    if (html.includes('vue') || html.includes('Vue')) {
      detections.push('Vue.js detected');
    }
    if (html.includes('angular') || html.includes('ng-')) {
      detections.push('Angular detected');
    }
    if (html.includes('jquery') || html.includes('jQuery')) {
      detections.push('jQuery detected');
    }
    
    return {
      title: 'TECHNOLOGY STACK',
      status: 'INFO',
      recommendation: 'Found technologies that may have security vulnerabilities if not kept updated. Always update to the latest versions!',
      details: {
        technologies: detections,
        note: 'Technology fingerprinting based on headers and content',
        explanation: 'Technologies are like the building blocks of your website - old versions can have security holes that hackers know how to exploit.',
        whyThisMatters: 'Outdated software is like having old locks on your doors - hackers know the weaknesses',
        securityAdvice: 'Regular updates are crucial - they patch security holes that hackers could use to break in'
      }
    };
  } catch (err) {
    return {
      title: 'TECHNOLOGY DETECTION',
      status: 'ERROR',
      recommendation: `Technology detection failed: ${err.message}`,
      error: err.message
    };
  }
}

// Scan endpoint
app.post('/api/scan', sessionMiddleware, sessionRateLimit, validateUrl, async (req, res) => {
  const { url } = req.body;
  const sessionId = req.headers['x-session-id'];
  
  // Check legal terms acceptance
  const legalTermsAccepted = req.headers['x-legal-accepted'];
  const legalTermsVersion = req.headers['x-legal-version'];
  
  if (!legalTermsAccepted || legalTermsVersion !== '1.0') {
    return res.status(403).json({ 
      success: false, 
      error: 'Legal terms must be accepted before scanning. Please read and accept the terms and conditions.' 
    });
  }
  
  try {
    console.log(`Starting scan for: ${url}`);
    
    // Log scan initiation
    await logLegalActivity('scan_initiated', {
      sessionId,
      userEmail: req.session.userEmail,
      username: req.session.username,
      targetUrl: url,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      legalTermsAccepted,
      legalTermsVersion
    });
    
    // Run all 6 security scans in parallel
    console.log('Starting 6 security scans...');
    const [headers, ssl, ports, tech, api, info] = await Promise.all([
      scanHeaders(url),
      scanSSL(url),
      scanPorts(url),
      detectTech(url),
      assessAPISecurity(url),
      assessInfoDisclosure(url)
    ]);
    console.log('All scans completed');

    const results = [headers, ssl, ports, tech, api, info];
    console.log(`Results count: ${results.length}`);
    
    // Store scan in session
    const scanData = {
      url,
      timestamp: new Date().toISOString(),
      results,
      scanId: crypto.randomUUID()
    };
    req.session.scans.push(scanData);
    
    // Log scan completion
    await logLegalActivity('scan_completed', {
      sessionId,
      userEmail: req.session.userEmail,
      username: req.session.username,
      targetUrl: url,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      legalTermsAccepted,
      legalTermsVersion,
      scanResults: results.map(r => ({ title: r.title, status: r.status }))
    });
    
    console.log(`Scan completed for: ${url} (Session: ${req.session.id})`);
    res.json({ 
      success: true, 
      ...scanData
    });
    
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Scan failed', 
      message: error.message 
    });
  }
});

// Generate PDF Report
async function generatePDFReport(scanResults, url, timestamp) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([595, 842]); // A4 size
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  
  let yPosition = 750;
  const lineHeight = 20;
  const marginLeft = 50;
  const pageWidth = 595;
  
  // Helper function to add text
  const addText = (text, fontUsed = font, fontSize = 12, color = rgb(0, 0, 0)) => {
    page.drawText(text, {
      x: marginLeft,
      y: yPosition,
      size: fontSize,
      font: fontUsed,
      color: color
    });
    yPosition -= lineHeight;
  };
  
  // Header
  addText('CyberShare Security Scan Report', boldFont, 24, rgb(0.2, 0.4, 0.8));
  yPosition -= 10;
  
  // Scan info
  addText(`Target URL: ${url}`, font, 12, rgb(0.3, 0.3, 0.3));
  addText(`Scan Date: ${new Date(timestamp).toLocaleString()}`, font, 12, rgb(0.3, 0.3, 0.3));
  addText(`Report Generated: ${new Date().toLocaleString()}`, font, 12, rgb(0.3, 0.3, 0.3));
  yPosition -= 20;
  
  // Results summary
  addText('Security Scan Results', boldFont, 18, rgb(0, 0, 0));
  yPosition -= 15;
  
  scanResults.forEach((result, index) => {
    // Check if we need a new page
    if (yPosition < 100) {
      const newPage = pdfDoc.addPage([595, 842]);
      yPosition = 750;
    }
    
    // Result title and status
    const statusColor = result.status === 'PASS' ? rgb(0, 0.6, 0) : 
                       result.status === 'FAIL' ? rgb(0.8, 0, 0) : 
                       result.status === 'WARN' ? rgb(0.8, 0.5, 0) : 
                       rgb(0.3, 0.3, 0.3);
    
    addText(`${index + 1}. ${result.title}`, boldFont, 14, statusColor);
    addText(`   Status: ${result.status}`, font, 12, statusColor);
    addText(`   Recommendation: ${result.recommendation}`, font, 11, rgb(0.2, 0.2, 0.2));
    
    // Add details if available
    if (result.details) {
      Object.keys(result.details).forEach(key => {
        if (Array.isArray(result.details[key])) {
          addText(`   ${key}: ${result.details[key].join(', ')}`, font, 10, rgb(0.4, 0.4, 0.4));
        } else {
          addText(`   ${key}: ${result.details[key]}`, font, 10, rgb(0.4, 0.4, 0.4));
        }
      });
    }
    
    yPosition -= 15;
  });
  
  // Footer
  yPosition = 50;
  addText('Generated by CyberShare Vulnerability Scanner', font, 10, rgb(0.5, 0.5, 0.5));
  addText('This report contains security recommendations based on automated scanning.', font, 9, rgb(0.6, 0.6, 0.6));
  
  return await pdfDoc.save();
}

// PDF download endpoint
app.post('/api/download-report', sessionMiddleware, validateScanData, async (req, res) => {
  const { results, url, timestamp } = req.body;
  
  if (!results || !url) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  try {
    const pdfBytes = await generatePDFReport(results, url, timestamp);
    
    // Set headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="cybershare-scan-report-${Date.now()}.pdf"`);
    res.setHeader('Content-Length', pdfBytes.length);
    
    res.send(Buffer.from(pdfBytes));
  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({ error: 'Failed to generate PDF report' });
  }
});

// Session management endpoint
app.get('/api/session', sessionMiddleware, (req, res) => {
  const session = req.session;
  res.json({
    sessionId: session.id,
    scanCount: session.scanCount,
    totalScans: session.scans.length,
    lastActivity: new Date(session.lastActivity).toISOString(),
    createdAt: new Date(session.createdAt).toISOString(),
    recentScans: session.scans.slice(-5).map(scan => ({
      url: scan.url,
      timestamp: scan.timestamp,
      scanId: scan.scanId
    }))
  });
});

// Clear session endpoint
app.delete('/api/session', sessionMiddleware, (req, res) => {
  const sessionId = req.session.id;
  sessions.delete(sessionId);
  res.json({
    success: true,
    message: 'Session cleared successfully'
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    activeSessions: sessions.size
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🛡️  CyberShare Scanner API running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔍 Scan endpoint: http://localhost:${PORT}/api/scan`);
});

export default app;

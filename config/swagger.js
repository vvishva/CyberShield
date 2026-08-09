const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'CyberShield AI Security API',
      version: '1.0.0',
      description: 'AI-Based Web Security Monitoring System - REST API Documentation',
      contact: {
        name: 'CyberShield Team',
        email: 'security@cybershield.io'
      },
      license: {
        name: 'ISC',
        url: 'https://opensource.org/licenses/ISC'
      }
    },
    servers: [
      {
        url: 'http://localhost:5000/api',
        description: 'Development server'
      },
      {
        url: 'https://cybershield-backend-uhwn.onrender.com/api',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            username: { type: 'string' },
            email: { type: 'string', format: 'email' },
            role: { type: 'string', enum: ['user', 'admin'] },
            avatar: { type: 'string' },
            twoFactorEnabled: { type: 'boolean' },
            emailNotifications: { type: 'boolean' },
            createdAt: { type: 'string', format: 'date-time' }
          }
        },
        Scan: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            user: { type: 'string' },
            scanType: { type: 'string', enum: ['url_phishing', 'website_security', 'ip_reputation', 'file_hash', 'password_check'] },
            target: { type: 'string' },
            status: { type: 'string', enum: ['Safe', 'Suspicious', 'Phishing', 'Medium Risk', 'High Risk', 'Weak', 'Strong'] },
            riskScore: { type: 'integer', minimum: 0, maximum: 100 },
            confidenceScore: { type: 'integer', minimum: 0, maximum: 100 },
            details: { type: 'object' },
            recommendations: { type: 'array', items: { type: 'string' } },
            createdAt: { type: 'string', format: 'date-time' }
          }
        },
        Report: {
          type: 'object',
          properties: {
            reportId: { type: 'string' },
            user: { type: 'string' },
            title: { type: 'string' },
            scanType: { type: 'string' },
            target: { type: 'string' },
            overallStatus: { type: 'string' },
            riskScore: { type: 'integer' },
            findings: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  category: { type: 'string' },
                  status: { type: 'string' },
                  detail: { type: 'string' }
                }
              }
            },
            recommendations: { type: 'array', items: { type: 'string' } },
            createdAt: { type: 'string', format: 'date-time' }
          }
        },
        SecurityTip: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            title: { type: 'string' },
            category: { type: 'string', enum: ['Password Safety', 'Phishing Awareness', 'Email Hygiene', 'Safe Browsing', 'Network Security', 'General Cyber'] },
            content: { type: 'string' },
            severity: { type: 'string', enum: ['INFO', 'IMPORTANT', 'CRITICAL'] },
            author: { type: 'string' },
            createdAt: { type: 'string', format: 'date-time' }
          }
        },
        Log: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            user: { type: 'string' },
            username: { type: 'string' },
            action: { type: 'string' },
            details: { type: 'string' },
            ipAddress: { type: 'string' },
            userAgent: { type: 'string' },
            status: { type: 'string', enum: ['SUCCESS', 'WARNING', 'FAILURE'] },
            createdAt: { type: 'string', format: 'date-time' }
          }
        },
        AuthResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            token: { type: 'string' },
            user: { $ref: '#/components/schemas/User' }
          }
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string' },
            details: { type: 'array', items: { type: 'object' } }
          }
        },
        ScanUrlRequest: {
          type: 'object',
          required: ['url'],
          properties: {
            url: { type: 'string', format: 'uri', example: 'https://example.com' }
          }
        },
        ScanWebsiteRequest: {
          type: 'object',
          required: ['url'],
          properties: {
            url: { type: 'string', format: 'uri', example: 'https://example.com' }
          }
        },
        ScanPasswordRequest: {
          type: 'object',
          required: ['password'],
          properties: {
            password: { type: 'string', example: 'Str0ng!Passw0rd' }
          }
        },
        ScanIpRequest: {
          type: 'object',
          required: ['ip'],
          properties: {
            ip: { type: 'string', example: '8.8.8.8' }
          }
        },
        ScanHashRequest: {
          type: 'object',
          properties: {
            md5: { type: 'string', pattern: '^[a-f0-9]{32}$' },
            sha1: { type: 'string', pattern: '^[a-f0-9]{40}$' },
            sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
            fileName: { type: 'string' }
          }
        },
        ScanUrlResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                scanId: { type: 'string' },
                target: { type: 'string' },
                status: { type: 'string' },
                riskScore: { type: 'integer' },
                confidenceScore: { type: 'integer' },
                modelUsed: { type: 'string' },
                features: { type: 'object' },
                recommendations: { type: 'array', items: { type: 'string' } }
              }
            }
          }
        },
        PasswordAnalysisResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                score: { type: 'integer' },
                strength: { type: 'string' },
                entropyBits: { type: 'integer' },
                timeToCrack: { type: 'string' },
                length: { type: 'integer' },
                checks: { type: 'object' },
                suggestions: { type: 'array', items: { type: 'string' } }
              }
            }
          }
        },
        WebsiteScanResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                url: { type: 'string' },
                domain: { type: 'string' },
                resolvedIp: { type: 'string' },
                protocol: { type: 'string' },
                securityScore: { type: 'integer' },
                riskLevel: { type: 'string' },
                hasHttps: { type: 'boolean' },
                sslValid: { type: 'boolean' },
                redirectChain: { type: 'array', items: { type: 'string' } },
                headerChecks: { type: 'object' },
                missingHeaders: { type: 'array', items: { type: 'string' } },
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                recommendations: { type: 'array', items: { type: 'string' } },
                scanDuration: { type: 'integer' },
                scannedAt: { type: 'string', format: 'date-time' }
              }
            }
          }
        },
        IpReputationResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                ip: { type: 'string' },
                country: { type: 'string' },
                city: { type: 'string' },
                isp: { type: 'string' },
                isProxy: { type: 'boolean' },
                isVpn: { type: 'boolean' },
                isTor: { type: 'boolean' },
                threatScore: { type: 'integer' },
                riskLevel: { type: 'string' },
                blacklistStatus: { type: 'string' },
                details: { type: 'array', items: { type: 'string' } }
              }
            }
          }
        },
        StatsResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                totalScans: { type: 'integer' },
                threatsDetected: { type: 'integer' },
                safeScans: { type: 'integer' },
                avgSecurityScore: { type: 'integer' },
                scansByType: { type: 'object' }
              }
            }
          }
        }
      }
    },
    security: [
      { bearerAuth: [] }
    ],
    tags: [
      { name: 'Authentication', description: 'User authentication and session management' },
      { name: 'Scans', description: 'Security scanning operations' },
      { name: 'Reports', description: 'Security report generation and management' },
      { name: 'User', description: 'User profile management' },
      { name: 'Admin', description: 'Administrative operations' },
      { name: 'Tips', description: 'Security tips and advisories' },
      { name: 'Events', description: 'Server-Sent Events for real-time updates' },
      { name: 'Monitor', description: 'Domain monitoring management' },
      { name: 'Health', description: 'System health checks' }
    ]
  },
  apis: ['./routes/*.js', './controllers/*.js']
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = swaggerSpec;
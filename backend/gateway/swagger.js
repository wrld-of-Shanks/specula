const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const version = require('./package.json').version;

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Specula — HORUS Security Scanner API',
      version,
      description:
        'A locally-trained security platform combining network intrusion detection (NIDS), ' +
        'source-code vulnerability detection (SAST), and dynamic application security testing ' +
        '(DAST) under one confidence-based triage engine.\n\n' +
        '## Authentication\n' +
        'All `/api/*` routes require an API key sent as the `X-Api-Key` header.\n\n' +
        '## Rate Limiting\n' +
        '| Endpoint Category | Limit |\n|---|---|\n' +
        '| General API calls | 60 requests/minute |\n' +
        '| Code/Network scans | 10 requests/minute |\n' +
        '| DAST scans | 5 requests/minute |\n' +
        '| Report generation | 10 requests/hour |\n' +
        '| Auto-fix operations | 20 requests/hour |\n\n' +
        '## Error Handling\n' +
        'All errors follow a consistent format:\n```json\n{"error": "Human-readable message"}\n```\n' +
        'Validation errors include an additional `details` array with field-specific messages.\n\n' +
        '## WebSocket\n' +
        'Connect to `ws://localhost:3000` for real-time event streaming. ' +
        'Authenticate by sending `{"api_key": "YOUR_KEY"}` as the first message after connection.'
    },
    servers: [
      { url: 'http://localhost:3000', description: 'Local gateway' }
    ],
    tags: [
      { name: 'Auth', description: 'API key required on all /api routes' },
      { name: 'Code (SAST)', description: 'Static code analysis — scan source code snippets for vulnerabilities' },
      { name: 'Repo Scan', description: 'Clone and scan entire GitHub repositories, with optional auto-fix PRs' },
      { name: 'Network (NIDS)', description: 'Behavioral network-traffic analysis for intrusion detection' },
      { name: 'DAST', description: 'Dynamic application security testing against live web applications' },
      { name: 'Events', description: 'Query and filter security findings/events from all scan types' },
      { name: 'Reports', description: 'Generate and download PDF security reports' },
      { name: 'Notifications', description: 'Slack / email security alert configuration' },
      { name: 'WebSocket', description: 'Real-time event stream via WebSocket connection' }
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'X-Api-Key',
          description: 'API key for authentication. Set `API_KEY` in your `.env` file. ' +
            'All /api/* endpoints require this header.'
        }
      },
      schemas: {
        Error: {
          type: 'object',
          description: 'Standard error response',
          properties: {
            error: {
              type: 'string',
              description: 'Human-readable error message',
              examples: [
                'Internal server error',
                'Code service unavailable',
                'DAST service unavailable',
                'Network service unavailable',
                'Event not found',
                'Scan job not found',
                'Report not found or expired',
                'Auto-fix is disabled (AUTO_FIX_ENABLED=false)',
                'Auto-fix is unavailable: GITHUB_TOKEN is not configured',
                'Auto-fix daily limit reached (max 50 per day)',
                'Invalid report filename',
                'Failed to download report',
                'Report generation failed',
                'Clone rejected: only github.com is allowed',
                'This finding does not reference a file (cannot auto-fix)',
                'Finding not found for this scan job',
                'Could not parse owner/repo from repo_url',
                'Failed to create report-only issue'
              ]
            }
          },
          example: { error: 'Internal server error' }
        },
        ValidationError: {
          type: 'object',
          description: 'Request validation failed — one or more fields are missing or invalid',
          properties: {
            error: {
              type: 'string',
              example: 'Validation failed'
            },
            details: {
              type: 'array',
              description: 'Field-level error messages',
              items: { type: 'string' },
              examples: [
                ['"code" is required', '"code" must be a string'],
                ['"target_url" is required', '"target_url" must be a valid URI'],
                ['"repo_url" is required', '"repo_url" must be a valid URI'],
                ['"finding_id" is required'],
                ['"job_id" is required'],
                ['"page" must be a number greater than or equal to 1'],
                ['"limit" must be a number between 1 and 1000'],
                ['"target" is required', '"target" is not allowed to be empty'],
                ['"event_type" must be one of [network, code, dast, scan_repo]'],
                ['"status" must be one of [auto_flagged, human_review, ignored]']
              ]
            }
          },
          example: { error: 'Validation failed', details: ['"code" is required', '"code" must be a string'] }
        },
        RateLimitError: {
          type: 'object',
          description: 'Rate limit exceeded',
          properties: {
            error: {
              type: 'string',
              example: 'Too many requests, please try again later'
            }
          },
          example: { error: 'Too many requests, please try again later' }
        },
        UnauthorizedError: {
          type: 'object',
          description: 'Missing or invalid API key',
          properties: {
            error: {
              type: 'string',
              example: 'Unauthorized: missing or invalid API key'
            }
          },
          example: { error: 'Unauthorized: missing or invalid API key' }
        },
        Event: {
          type: 'object',
          description: 'A security event/finding from any scan type',
          properties: {
            _id: {
              type: 'string',
              description: 'Unique event identifier (MongoDB ObjectId)',
              example: '507f1f77bcf86cd799439011'
            },
            event_type: {
              type: 'string',
              enum: ['network', 'code', 'dast', 'scan_repo'],
              description: 'Type of scan that produced this event',
              example: 'code'
            },
            timestamp: {
              type: 'string',
              format: 'date-time',
              description: 'ISO 8601 timestamp when the event was created',
              example: '2026-08-28T12:00:00.000Z'
            },
            source: {
              type: 'string',
              description: 'Source of the scan (manual_scan, repo URL, IP address, etc.)',
              example: 'manual_scan'
            },
            prediction: {
              type: 'string',
              description: 'Classified vulnerability type or status',
              enum: ['sql_injection', 'xss', 'command_injection', 'hardcoded_credentials', 'path_traversal', 'insecure_deserialization', 'not_vulnerable', 'anomaly', 'normal'],
              example: 'sql_injection'
            },
            confidence: {
              type: 'number',
              minimum: 0,
              maximum: 1,
              nullable: true,
              description: 'Model confidence score (0.0 - 1.0). Null for confirmed findings.',
              example: 0.92
            },
            certainty_type: {
              type: 'string',
              enum: ['confirmed', 'inferred', null],
              description: 'Whether the finding is confirmed (rule-matched) or inferred (model-predicted)',
              example: 'inferred'
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Triage severity level assigned by the engine',
              example: 'high'
            },
            status: {
              type: 'string',
              enum: ['auto_flagged', 'human_review', 'ignored'],
              description: 'Triage status — auto_flagged for high-confidence, human_review for medium, ignored for low',
              example: 'auto_flagged'
            },
            explanation: {
              type: 'object',
              nullable: true,
              description: 'Detailed explanation of the finding',
              properties: {
                what: { type: 'string', description: 'Description of the vulnerability', example: 'SQL query uses string concatenation with user input' },
                why: { type: 'string', description: 'Why this is a security risk', example: 'Allows SQL injection attacks' },
                where: { type: 'string', description: 'Location in code or network', example: 'Line 5 in app.py' },
                reference: {
                  type: 'object',
                  description: 'External reference links',
                  properties: {
                    cwe: { type: 'string', description: 'Common Weakness Enumeration ID', example: 'CWE-89' },
                    owasp: { type: 'string', description: 'OWASP Top 10 category', example: 'A03:2021-Injection' }
                  }
                },
                remediation: {
                  type: 'object',
                  description: 'Fix recommendations',
                  properties: {
                    guidance: { type: 'string', description: 'Remediation guidance text', example: 'Use parameterized queries instead of string concatenation' },
                    suggested_code_fix: { type: 'string', nullable: true, description: 'Auto-generated code fix (if available)' }
                  }
                }
              }
            },
            suggested_fix: {
              type: 'string',
              nullable: true,
              description: 'Auto-generated fix suggestion (for code scans)',
              example: 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
            },
            file_path: {
              type: 'string',
              nullable: true,
              description: 'Relative file path (for repo scans)',
              example: 'src/app.py'
            },
            line_range: {
              type: 'object',
              nullable: true,
              description: 'Line range in the file',
              properties: {
                start: { type: 'integer', example: 10 },
                end: { type: 'integer', example: 15 }
              }
            },
            job_id: {
              type: 'string',
              nullable: true,
              description: 'Associated scan job ID (for repo scans)',
              example: '507f1f77bcf86cd799439012'
            },
            mode: {
              type: 'string',
              enum: ['passive', 'active'],
              nullable: true,
              description: 'DAST scan mode',
              example: 'passive'
            },
            evidence: {
              type: 'object',
              nullable: true,
              description: 'Raw evidence data (only included when verbose_evidence=true)'
            }
          }
        },
        ScanJob: {
          type: 'object',
          description: 'Repository scan job status and metadata',
          properties: {
            _id: {
              type: 'string',
              description: 'Job ID',
              example: '507f1f77bcf86cd799439013'
            },
            repo_url: {
              type: 'string',
              description: 'GitHub repository URL',
              example: 'https://github.com/octocat/Hello-World'
            },
            status: {
              type: 'string',
              enum: ['pending', 'cloning', 'scanning', 'completed', 'failed'],
              description: 'Current job status',
              example: 'completed'
            },
            file_count: {
              type: 'integer',
              description: 'Number of source files scanned',
              example: 42
            },
            finding_count: {
              type: 'integer',
              description: 'Number of vulnerabilities found',
              example: 5
            },
            error: {
              type: 'string',
              nullable: true,
              description: 'Error message if job failed',
              example: null
            },
            started_at: {
              type: 'string',
              format: 'date-time',
              description: 'Job start time',
              example: '2026-08-28T12:00:00.000Z'
            },
            completed_at: {
              type: 'string',
              format: 'date-time',
              nullable: true,
              description: 'Job completion time',
              example: '2026-08-28T12:05:00.000Z'
            }
          }
        },
        AuthorizedTarget: {
          type: 'object',
          description: 'Host authorized for active DAST scanning',
          properties: {
            target: {
              type: 'string',
              description: 'Hostname (e.g., example.com)',
              example: 'example.com'
            },
            note: {
              type: 'string',
              description: 'Authorization note',
              example: 'Production staging server'
            },
            added_at: {
              type: 'string',
              format: 'date-time',
              description: 'When the target was authorized',
              example: '2026-08-28T12:00:00.000Z'
            }
          }
        },
        DastFinding: {
          type: 'object',
          description: 'A single DAST finding from a scan',
          properties: {
            event_id: {
              type: 'string',
              description: 'Event ID for this finding',
              example: '507f1f77bcf86cd799439014'
            },
            prediction: {
              type: 'string',
              description: 'Check type or name that detected the issue',
              example: 'missing_security_headers'
            },
            confidence: {
              type: 'number',
              nullable: true,
              description: 'Confidence score (null for confirmed findings)',
              example: 0.85
            },
            certainty_type: {
              type: 'string',
              enum: ['confirmed', 'inferred'],
              description: 'Whether the finding is confirmed or inferred',
              example: 'confirmed'
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Triage severity',
              example: 'medium'
            },
            status: {
              type: 'string',
              enum: ['auto_flagged', 'human_review', 'ignored'],
              description: 'Triage status',
              example: 'auto_flagged'
            },
            explanation: {
              type: 'object',
              nullable: true,
              description: 'Detailed explanation of the finding'
            }
          }
        },
        CodeScanResult: {
          type: 'object',
          description: 'Result from a code snippet scan',
          properties: {
            event_id: {
              type: 'string',
              description: 'Event ID for this scan result',
              example: '507f1f77bcf86cd799439015'
            },
            prediction: {
              type: 'string',
              enum: ['sql_injection', 'xss', 'command_injection', 'hardcoded_credentials', 'path_traversal', 'insecure_deserialization', 'not_vulnerable'],
              description: 'Detected vulnerability type',
              example: 'sql_injection'
            },
            confidence: {
              type: 'number',
              minimum: 0,
              maximum: 1,
              description: 'Classification confidence',
              example: 0.92
            },
            certainty_type: {
              type: 'string',
              enum: ['confirmed', 'inferred'],
              description: 'Certainty level',
              example: 'inferred'
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Triage severity',
              example: 'high'
            },
            status: {
              type: 'string',
              enum: ['auto_flagged', 'human_review', 'ignored'],
              description: 'Triage status',
              example: 'auto_flagged'
            },
            explanation: {
              type: 'object',
              nullable: true,
              description: 'Detailed explanation of the vulnerability'
            },
            suggested_fix: {
              type: 'string',
              nullable: true,
              description: 'Suggested code fix',
              example: 'Use parameterized queries'
            },
            top_predictions: {
              type: 'array',
              description: 'Top 3 prediction candidates with confidence scores',
              items: {
                type: 'object',
                properties: {
                  class: { type: 'string', example: 'sql_injection' },
                  cwe: { type: 'string', example: 'CWE-89' },
                  confidence: { type: 'number', example: 0.92 }
                }
              }
            }
          }
        },
        NetworkAnalysisResult: {
          type: 'object',
          description: 'Result from network traffic analysis',
          properties: {
            event_id: {
              type: 'string',
              description: 'Event ID',
              example: '507f1f77bcf86cd799439016'
            },
            prediction: {
              type: 'string',
              enum: ['anomaly', 'normal'],
              description: 'Traffic classification',
              example: 'anomaly'
            },
            confidence: {
              type: 'number',
              nullable: true,
              description: 'Classification confidence',
              example: 0.88
            },
            certainty_type: {
              type: 'string',
              description: 'Certainty level',
              example: 'inferred'
            },
            anomaly_score: {
              type: 'number',
              nullable: true,
              description: 'Isolation Forest anomaly score',
              example: 0.75
            },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low', 'info'],
              description: 'Triage severity',
              example: 'high'
            },
            status: {
              type: 'string',
              enum: ['auto_flagged', 'human_review', 'ignored'],
              description: 'Triage status',
              example: 'auto_flagged'
            },
            explanation: {
              type: 'object',
              nullable: true,
              description: 'Detailed explanation of the anomaly'
            }
          }
        },
        DastScanResult: {
          type: 'object',
          description: 'Result from a DAST scan',
          properties: {
            target_url: {
              type: 'string',
              description: 'Scanned target URL',
              example: 'http://localhost:8080'
            },
            mode: {
              type: 'string',
              enum: ['passive', 'active'],
              description: 'Scan mode used',
              example: 'passive'
            },
            finding_count: {
              type: 'integer',
              description: 'Number of findings detected',
              example: 3
            },
            findings: {
              type: 'array',
              description: 'Array of detected security issues',
              items: {
                $ref: '#/components/schemas/DastFinding'
              }
            }
          }
        },
        RepoScanStartResult: {
          type: 'object',
          description: 'Response when a repo scan job is started',
          properties: {
            job_id: {
              type: 'string',
              description: 'Job ID for tracking progress',
              example: '507f1f77bcf86cd799439017'
            },
            status: {
              type: 'string',
              enum: ['cloning'],
              description: 'Initial job status',
              example: 'cloning'
            },
            message: {
              type: 'string',
              description: 'Status message',
              example: 'Repository scan started'
            }
          }
        },
        RepoScanJobResult: {
          type: 'object',
          description: 'Detailed repo scan job with findings grouped by file',
          properties: {
            job: {
              $ref: '#/components/schemas/ScanJob'
            },
            findings: {
              type: 'object',
              description: 'Findings grouped by file path',
              additionalProperties: {
                type: 'array',
                items: {
                  $ref: '#/components/schemas/Event'
                }
              },
              example: {
                "src/app.py": [
                  { "_id": "507f1f77bcf86cd799439011", "prediction": "sql_injection", "confidence": 0.92 }
                ],
                "src/utils.py": []
              }
            }
          }
        },
        AutoFixResult: {
          type: 'object',
          description: 'Result from an auto-fix operation',
          properties: {
            success: {
              type: 'boolean',
              description: 'Whether the operation succeeded',
              example: true
            },
            pr_url: {
              type: 'string',
              nullable: true,
              description: 'URL of the created pull request (if fix was generated)',
              example: 'https://github.com/octocat/Hello-World/pull/42'
            },
            issue_url: {
              type: 'string',
              nullable: true,
              description: 'URL of the created issue (if report-only fallback)',
              example: 'https://github.com/octocat/Hello-World/issues/100'
            },
            branch: {
              type: 'string',
              nullable: true,
              description: 'Branch name where fix was committed',
              example: 'auto-fix/sql-injection-abc123'
            },
            fallback: {
              type: 'boolean',
              description: 'Whether a report-only issue was created instead of a PR',
              example: false
            },
            message: {
              type: 'string',
              description: 'Human-readable result message',
              example: 'Pull request created successfully'
            }
          }
        },
        ReportResult: {
          type: 'object',
          description: 'Result from report generation',
          properties: {
            success: {
              type: 'boolean',
              description: 'Whether the report was generated',
              example: true
            },
            report_url: {
              type: 'string',
              description: 'Relative URL to download the report',
              example: '/api/reports/reports/report_20260828_120000_abc123.pdf'
            },
            download_link: {
              type: 'string',
              description: 'Full URL to download the report',
              example: 'http://localhost:3000/api/reports/reports/report_20260828_120000_abc123.pdf'
            },
            message: {
              type: 'string',
              description: 'Status message with finding count',
              example: 'Report generated successfully (15 findings)'
            }
          }
        },
        WebSocketAuthMessage: {
          type: 'object',
          description: 'WebSocket authentication message — send immediately after connection',
          properties: {
            api_key: {
              type: 'string',
              description: 'Your API key',
              example: '150a3c84395e0ef26fc8f14884d94e0cf846b2fa1f784ffc52e2440ecd868e4a'
            }
          }
        },
        WebSocketEvent: {
          type: 'object',
          description: 'Real-time event broadcast via WebSocket',
          properties: {
            type: {
              type: 'string',
              enum: ['new_event'],
              description: 'Message type',
              example: 'new_event'
            },
            data: {
              $ref: '#/components/schemas/Event'
            }
          }
        }
      }
    },
    security: [{ ApiKeyAuth: [] }]
  },
  apis: ['./routes/*.js']
};

const spec = swaggerJSDoc(options);

module.exports = {
  swaggerSpec: spec,
  swaggerUiServe: swaggerUi.serve,
  swaggerUiSetup: swaggerUi.setup(spec, {
    customSiteTitle: 'Specula API Docs',
    customCss: '.swagger-ui .topbar { display: none }',
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      filter: true,
      tryItOutEnabled: true
    }
  })
};

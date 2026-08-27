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
        'All `/api/*` routes require an API key sent as the `X-Api-Key` header.'
    },
    servers: [
      { url: 'http://localhost:3000', description: 'Local gateway' }
    ],
    tags: [
      { name: 'Auth', description: 'API key required on all /api routes' },
      { name: 'Code (SAST)', description: 'Static code analysis' },
      { name: 'Repo Scan', description: 'Clone & scan a GitHub repository' },
      { name: 'Network (NIDS)', description: 'Behavioral network-traffic analysis' },
      { name: 'DAST', description: 'Dynamic application security testing' },
      { name: 'Events', description: 'Scan findings / event feed' },
      { name: 'Reports', description: 'PDF report generation & download' },
      { name: 'Notifications', description: 'Slack / email security alerts' },
      { name: 'WebSocket', description: 'Real-time event stream' }
    ],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'X-Api-Key',
          description: 'API key. Set `API_KEY` in your `.env`.'
        }
      },
      schemas: {
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string', description: 'Human-readable error message' }
          }
        },
        ValidationError: {
          type: 'object',
          properties: {
            error: { type: 'string', example: 'Validation failed' },
            details: { type: 'array', items: { type: 'string' } }
          }
        },
        Event: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            event_type: { enum: ['network', 'code', 'dast', 'scan_repo'] },
            timestamp: { type: 'string', format: 'date-time' },
            source: { type: 'string' },
            prediction: { type: 'string' },
            confidence: { type: 'number', minimum: 0, maximum: 1, nullable: true },
            certainty_type: { enum: ['confirmed', 'inferred', null] },
            severity: { enum: ['critical', 'high', 'medium', 'low', 'info'] },
            status: { enum: ['auto_flagged', 'human_review', 'ignored'] },
            explanation: { type: 'object', nullable: true },
            suggested_fix: { type: 'string', nullable: true },
            file_path: { type: 'string', nullable: true }
          }
        },
        ScanJob: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            repo_url: { type: 'string' },
            status: { enum: ['pending', 'cloning', 'scanning', 'completed', 'failed'] },
            file_count: { type: 'integer' },
            finding_count: { type: 'integer' },
            error: { type: 'string', nullable: true },
            started_at: { type: 'string', format: 'date-time' },
            completed_at: { type: 'string', format: 'date-time', nullable: true }
          }
        },
        AuthorizedTarget: {
          type: 'object',
          properties: {
            target: { type: 'string' },
            note: { type: 'string' },
            added_at: { type: 'string', format: 'date-time' }
          }
        },
        DastFinding: {
          type: 'object',
          properties: {
            event_id: { type: 'string' },
            prediction: { type: 'string' },
            confidence: { type: 'number', nullable: true },
            certainty_type: { type: 'string' },
            severity: { type: 'string' },
            status: { type: 'string' },
            explanation: { type: 'object', nullable: true }
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
    customSiteTitle: 'Specula API Docs'
  })
};

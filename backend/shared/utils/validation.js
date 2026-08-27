const Joi = require('joi');

const MAX_CODE_LENGTH = 50000;
const MAX_URL_LENGTH = 2048;
const MAX_TARGET_URL_LENGTH = 2048;

const networkAnalyzeSchema = Joi.object({
  protocol_type: Joi.string().valid('tcp', 'udp', 'icmp').optional(),
  service: Joi.string().max(50).optional(),
  flag: Joi.string().max(10).optional(),
  src_bytes: Joi.number().integer().min(0).optional(),
  dst_bytes: Joi.number().integer().min(0).optional(),
  duration: Joi.number().min(0).optional(),
  count: Joi.number().integer().min(0).optional(),
  srv_count: Joi.number().integer().min(0).optional(),
  serror_rate: Joi.number().min(0).max(1).optional(),
  srv_serror_rate: Joi.number().min(0).max(1).optional(),
  rerror_rate: Joi.number().min(0).max(1).optional(),
  srv_rerror_rate: Joi.number().min(0).max(1).optional(),
  same_srv_rate: Joi.number().min(0).max(1).optional(),
  diff_srv_rate: Joi.number().min(0).max(1).optional(),
  dst_host_count: Joi.number().integer().min(0).optional(),
  dst_host_srv_count: Joi.number().integer().min(0).optional(),
  dst_host_same_srv_rate: Joi.number().min(0).max(1).optional(),
  dst_host_diff_srv_rate: Joi.number().min(0).max(1).optional(),
  dst_host_serror_rate: Joi.number().min(0).max(1).optional(),
  dst_host_rerror_rate: Joi.number().min(0).max(1).optional(),
  source: Joi.string().max(200).optional()
}).options({ stripUnknown: true });

const codeScanSchema = Joi.object({
  code: Joi.string().min(1).max(MAX_CODE_LENGTH).required()
});

const scanRepoSchema = Joi.object({
  repo_url: Joi.string().uri({ scheme: ['https'] }).max(MAX_URL_LENGTH).required()
    .pattern(/^https:\/\/github\.com\/[\w.\-]+\/[\w.\-]+(?:\.git)?$/)
});

const dastScanSchema = Joi.object({
  target_url: Joi.string().max(MAX_TARGET_URL_LENGTH).required()
    .custom((value, helpers) => {
      let url = value.trim();
      if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
      }
      try {
        new URL(url);
      } catch {
        return helpers.error('any.invalid');
      }
      return url;
    }),
  mode: Joi.string().valid('passive', 'active').default('passive'),
  verbose_evidence: Joi.boolean().default(false)
});

const authorizedTargetSchema = Joi.object({
  target: Joi.string().max(253).required(),
  note: Joi.string().max(500).optional()
});

const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(50),
  event_type: Joi.string().valid('network', 'code', 'dast', 'scan_repo').optional(),
  status: Joi.string().valid('auto_flagged', 'human_review', 'ignored').optional(),
  since: Joi.string().isoDate().optional()
});

function validate(schema, source = 'body') {
  return (req, res, next) => {
    const data = source === 'query' ? req.query : req[source];
    const { error, value } = schema.validate(data, { abortEarly: false, stripUnknown: true });
    if (error) {
      const details = error.details.map(d => d.message);
      return res.status(400).json({ error: 'Validation failed', details });
    }
    req[source] = value;
    next();
  };
}

module.exports = {
  networkAnalyzeSchema,
  codeScanSchema,
  scanRepoSchema,
  dastScanSchema,
  authorizedTargetSchema,
  paginationSchema,
  validate,
  MAX_CODE_LENGTH,
  MAX_URL_LENGTH
};

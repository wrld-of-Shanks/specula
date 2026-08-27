import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE || '';

const headers = {
  'Content-Type': 'application/json'
};

const API_KEY = process.env.REACT_APP_API_KEY;
if (API_KEY) {
  headers['X-Api-Key'] = API_KEY;
}

const api = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
  headers
});

export const fetchEvents = async (params = {}) => {
  const response = await api.get('/api/events', { params });
  return response.data.events || response.data;
};

export const fetchEventById = async (id) => {
  const response = await api.get(`/api/events/${id}`);
  return response.data;
};

export const fetchStats = async () => {
  const response = await api.get('/api/events/stats/summary');
  return response.data;
};

export const analyzeNetwork = async (data) => {
  const response = await api.post('/api/network/analyze', data);
  return response.data;
};

export const scanCode = async (code) => {
  const response = await api.post('/api/code/scan', { code });
  return response.data;
};

export const scanRepo = async (repoUrl) => {
  const response = await api.post('/api/code/scan-repo', { repo_url: repoUrl });
  return response.data;
};

export const getScanJobs = async () => {
  const response = await api.get('/api/code/scan-repo');
  return response.data;
};

export const getScanJob = async (jobId) => {
  const response = await api.get(`/api/code/scan-repo/${jobId}`);
  return response.data;
};

export const dastScan = async (targetUrl, mode = 'passive', verboseEvidence = false) => {
  const response = await api.post('/api/dast/scan', {
    target_url: targetUrl,
    mode,
    verbose_evidence: verboseEvidence
  });
  return response.data;
};

export const getAuthorizedTargets = async () => {
  const response = await api.get('/api/dast/authorized-targets');
  return response.data;
};

export const addAuthorizedTarget = async (target, note = '') => {
  const response = await api.post('/api/dast/authorized-targets', { target, note });
  return response.data;
};

export const removeAuthorizedTarget = async (target) => {
  const response = await api.delete(`/api/dast/authorized-targets/${encodeURIComponent(target)}`);
  return response.data;
};

export const autoFixFinding = async (jobId, findingId) => {
  const response = await api.post(`/api/code/scan-repo/${jobId}/fix`, { finding_id: findingId });
  return response.data;
};

export const generateReport = async (jobId, opts = {}) => {
  const response = await api.post('/api/reports/generate', {
    job_id: jobId,
    format: 'pdf',
    include_fixes: opts.includeFixes !== false,
    ...(opts.timeRange ? { time_range: opts.timeRange } : {})
  });
  return response.data;
};

export const sendNotification = async (jobId, channels = ['slack', 'email'], recipients = []) => {
  const response = await api.post('/api/notifications/send', {
    job_id: jobId,
    channels,
    ...(recipients.length ? { recipients } : {})
  });
  return response.data;
};

export const downloadReport = async (reportUrl) => {
  const response = await api.get(reportUrl, { responseType: 'blob' });
  const disposition = response.headers['content-disposition'] || '';
  let filename = 'report.pdf';
  const match = disposition.match(/filename="?([^"]+)"?/);
  if (match) filename = match[1];
  const blobURL = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = blobURL;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(blobURL);
  return filename;
};

export default api;

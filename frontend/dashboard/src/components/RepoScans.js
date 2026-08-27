import React, { useState, useEffect } from 'react';
import { GitBranch, Search, AlertTriangle, CheckCircle, Clock, FileCode, ExternalLink, FileText, Send, Download } from 'lucide-react';
import { scanRepo, getScanJobs, getScanJob, autoFixFinding, generateReport, sendNotification, downloadReport } from '../services/api';
import FindingCard from './FindingCard';

const RepoScans = () => {
  const [repoUrl, setRepoUrl] = useState('');
  const [jobs, setJobs] = useState([]);
  const [selectedJob, setSelectedJob] = useState(null);
  const [jobDetails, setJobDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [fixingId, setFixingId] = useState(null);
  const [fixResult, setFixResult] = useState(null);
  const [reporting, setReporting] = useState(false);
  const [reportResult, setReportResult] = useState(null);
  const [notifying, setNotifying] = useState(false);
  const [notifyResult, setNotifyResult] = useState(null);
  const [notifyChannels, setNotifyChannels] = useState({ slack: false, email: false });

  useEffect(() => {
    loadJobs();
  }, []);

  const loadJobs = async () => {
    try {
      setLoading(true);
      const data = await getScanJobs();
      setJobs(data);
    } catch (err) {
      setError('Failed to load scan jobs');
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async () => {
    if (!repoUrl.trim()) return;
    const url = repoUrl.trim();
    setScanning(true);
    setError(null);
    try {
      await scanRepo(url);
      setRepoUrl('');
      setTimeout(loadJobs, 2000);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan');
    } finally {
      setScanning(false);
    }
  };

  const handleViewJob = async (jobId) => {
    try {
      setSelectedJob(jobId);
      const data = await getScanJob(jobId);
      setJobDetails(data);
    } catch (err) {
      setError('Failed to load job details');
    }
  };

  const handleAutoFix = async (finding, jobId) => {
    setFixingId(finding._id);
    setFixResult(null);
    try {
      const result = await autoFixFinding(jobId, finding._id);
      setFixResult(result);
    } catch (err) {
      setFixResult({ error: err.response?.data?.error || err.message || 'Auto-fix failed' });
    } finally {
      setFixingId(null);
    }
  };

  const handleGenerateReport = async () => {
    if (!selectedJob) return;
    setReporting(true);
    setReportResult(null);
    try {
      const result = await generateReport(selectedJob, { includeFixes: true });
      setReportResult({ success: true, download_link: result.download_link, report_url: result.report_url, message: result.message });
    } catch (err) {
      setReportResult({ error: err.response?.data?.error || err.message || 'Report generation failed' });
    } finally {
      setReporting(false);
    }
  };

  const handleDownloadReport = async (reportUrl) => {
    try {
      await downloadReport(reportUrl);
    } catch (err) {
      setReportResult({ error: err.response?.data?.error || err.message || 'Download failed' });
    }
  };

  const toggleNotifyChannel = (channel) => {
    setNotifyChannels(prev => ({ ...prev, [channel]: !prev[channel] }));
  };

  const handleSendNotification = async () => {
    if (!selectedJob) return;
    const channels = Object.keys(notifyChannels).filter(c => notifyChannels[c]);
    if (channels.length === 0) {
      setNotifyResult({ error: 'Select at least one notification channel' });
      return;
    }
    setNotifying(true);
    setNotifyResult(null);
    try {
      const result = await sendNotification(selectedJob, channels);
      setNotifyResult(result);
    } catch (err) {
      setNotifyResult({ error: err.response?.data?.error || err.message || 'Notification send failed' });
    } finally {
      setNotifying(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return '#10b981';
      case 'failed': return '#ef4444';
      case 'scanning': case 'cloning': return '#eab308';
      default: return '#64748b';
    }
  };

  return (
    <div className="repo-scans">
      <h2><GitBranch className="icon" /> Repository SAST Scanner</h2>

      <div className="scan-input-group">
        <input
          type="url"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          className="repo-input"
        />
        <button onClick={handleScan} disabled={scanning || !repoUrl.trim()} className="scan-button">
          {scanning ? 'Starting...' : <><Search className="icon" /> Scan Repository</>}
        </button>
      </div>

      {error && <div className="error-message"><AlertTriangle className="icon" /> {error}</div>}

      <div className="jobs-section">
        <h3>Scan Jobs</h3>
        {loading ? <div className="loading">Loading...</div> : (
          <div className="jobs-list">
            {jobs.length === 0 ? (
              <div className="no-events"><p>No scan jobs yet</p></div>
            ) : jobs.map(job => (
              <div key={job._id} className={`job-card ${selectedJob === job._id ? 'selected' : ''}`}
                onClick={() => handleViewJob(job._id)}>
                <div className="job-header">
                  <span className="job-repo">{job.repo_url}</span>
                  <span className="status-badge" style={{ backgroundColor: getStatusColor(job.status) }}>
                    {job.status}
                  </span>
                </div>
                <div className="job-meta">
                  <span><FileCode className="icon-sm" /> {job.file_count} files</span>
                  <span><AlertTriangle className="icon-sm" /> {job.finding_count} findings</span>
                  <span><Clock className="icon-sm" /> {new Date(job.started_at).toLocaleString()}</span>
                </div>
                {job.status === 'failed' && job.error && (
                  <div className="job-error">{job.error}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {jobDetails && (
        <div className="job-details">
          <h3>Findings: {jobDetails.repo_url}</h3>
          {fixResult && (
            <div className={`fix-result ${fixResult.error ? 'error' : 'success'}`}>
              {fixResult.pr_url && (
                <a href={fixResult.pr_url} target="_blank" rel="noopener noreferrer">
                  <ExternalLink size={16} /> View Pull Request
                </a>
              )}
              {fixResult.issue_url && (
                <a href={fixResult.issue_url} target="_blank" rel="noopener noreferrer">
                  <ExternalLink size={16} /> View Issue (fallback)
                </a>
              )}
              {fixResult.message && <p>{fixResult.message}</p>}
              {fixResult.error && <p className="error-text">{fixResult.error}</p>}
            </div>
          )}

          <div className="report-toolbar">
            <button className="report-btn" onClick={handleGenerateReport} disabled={reporting}>
              {reporting ? 'Generating...' : <><FileText size={14} /> Generate Report</>}
            </button>
            {reportResult && reportResult.success && (
              <button className="report-btn download" onClick={() => handleDownloadReport(reportResult.report_url)}>
                <Download size={14} /> Download PDF
              </button>
            )}
          </div>
          {reportResult && (
            <div className={`fix-result ${reportResult.error ? 'error' : 'success'}`}>
              {reportResult.message && <p>{reportResult.message}</p>}
              {reportResult.error && <p className="error-text">{reportResult.error}</p>}
            </div>
          )}

          <div className="notify-toolbar">
            <span className="notify-label"><Send size={14} /> Notify:</span>
            <label className="notify-check">
              <input type="checkbox" checked={notifyChannels.slack} onChange={() => toggleNotifyChannel('slack')} /> Slack
            </label>
            <label className="notify-check">
              <input type="checkbox" checked={notifyChannels.email} onChange={() => toggleNotifyChannel('email')} /> Email
            </label>
            <button className="report-btn notify" onClick={handleSendNotification} disabled={notifying}>
              {notifying ? 'Sending...' : 'Send Notification'}
            </button>
          </div>
          {notifyResult && (
            <div className={`fix-result ${notifyResult.error ? 'error' : 'success'}`}>
              {notifyResult.slack_sent && <p>✓ Slack sent</p>}
              {notifyResult.email_sent && <p>✓ Email sent</p>}
              {notifyResult.message && <p>{notifyResult.message}</p>}
              {notifyResult.error && <p className="error-text">{notifyResult.error}</p>}
            </div>
          )}

          <div className="findings-by-file">
            {Object.entries(jobDetails.findings).map(([filePath, findings]) => (
              <div key={filePath} className="file-group">
                <h4 className="file-path">{filePath}</h4>
                {findings.map((f, i) => (
                  <FindingCard
                    key={f._id || i}
                    event={f}
                    showType={false}
                    showFile={false}
                    onAutoFix={handleAutoFix}
                    fixing={fixingId === f._id}
                    jobId={selectedJob}
                  />
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default RepoScans;

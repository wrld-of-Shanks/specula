import React, { useState, useEffect } from 'react';
import { GitBranch, Search, AlertTriangle, CheckCircle, Clock, FileCode } from 'lucide-react';
import { scanRepo, getScanJobs, getScanJob } from '../services/api';
import FindingCard from './FindingCard';

const RepoScans = () => {
  const [repoUrl, setRepoUrl] = useState('');
  const [jobs, setJobs] = useState([]);
  const [selectedJob, setSelectedJob] = useState(null);
  const [jobDetails, setJobDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

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
          <div className="findings-by-file">
            {Object.entries(jobDetails.findings).map(([filePath, findings]) => (
              <div key={filePath} className="file-group">
                <h4 className="file-path">{filePath}</h4>
                {findings.map((f, i) => (
                  <FindingCard key={f._id || i} event={f} showType={false} showFile={false} />
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

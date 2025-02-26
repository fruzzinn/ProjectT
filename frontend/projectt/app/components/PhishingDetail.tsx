import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface PhishingSite {
  id: string;
  url: string;
  domain: string;
  status: 'active' | 'monitoring' | 'taken-down';
  first_detected: string;
  last_checked: string;
  similarity_score: number;
  visual_similarity?: number;
  content_similarity?: number;
  url_similarity?: number;
  ml_confidence?: number;
  features_detected: string[];
  ip_address?: string;
  country_code?: string;
  hosting_provider?: string;
  registration_date?: string;
  has_login_form: boolean;
  has_tamm_logo: boolean;
  screenshot_path?: string;
  target_page: string;
  html_content?: string;
  form_targets?: Array<{
    action: string;
    method: string;
  }>;
  registrar?: string;
}

interface PhishingDetailProps {
  siteId: string;
  onClose: () => void;
}

const PhishingDetail: React.FC<PhishingDetailProps> = ({ siteId, onClose }) => {
  const [site, setSite] = useState<PhishingSite | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'technical' | 'content'>('overview');

  useEffect(() => {
    const fetchSiteDetail = async () => {
      try {
        setLoading(true);
        // In a real implementation, this would be a valid API endpoint
        const response = await fetch(`/api/phishing/sites/${siteId}`);
        
        if (!response.ok) {
          throw new Error(`Error fetching site: ${response.statusText}`);
        }
        
        const data = await response.json();
        setSite(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    };
    
    fetchSiteDetail();
  }, [siteId]);

  // Update site status
  const updateSiteStatus = async (status: string) => {
    try {
      const response = await fetch(`/api/phishing/sites/${siteId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status }),
      });
      
      if (!response.ok) {
        throw new Error(`Error updating site: ${response.statusText}`);
      }
      
      const updatedSite = await response.json();
      setSite(updatedSite);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred updating the site');
    }
  };

  // Report site
  const reportSite = async () => {
    try {
      const response = await fetch(`/api/phishing/report/${siteId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          report_details: "Reported from phishing dashboard"
        }),
      });
      
      if (!response.ok) {
        throw new Error(`Error reporting site: ${response.statusText}`);
      }
      
      alert('Site reported successfully');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred reporting the site');
    }
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-dark-cyan"></div>
      </div>
    );
  }

  if (error || !site) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
        <div className="bg-gray-900 rounded-lg p-6 max-w-2xl w-full">
          <h2 className="text-xl font-bold text-red-500 mb-4">Error</h2>
          <p className="text-white mb-4">{error || 'Site not found'}</p>
          <button 
            onClick={onClose}
            className="px-4 py-2 bg-gray-800 text-white rounded hover:bg-gray-700"
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <motion.div 
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className="bg-gray-900 rounded-lg p-6 max-w-4xl w-full my-8"
      >
        <div className="flex justify-between items-start mb-4">
          <h2 className="text-2xl font-bold text-dark-cyan">Phishing Site Details</h2>
          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-white"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div className="mb-6">
          <h3 className="text-xl text-white font-bold mb-2 break-all">{site.url}</h3>
          <div className="flex flex-wrap gap-2 mb-4">
            <span className={`px-2 py-1 rounded text-xs ${
              site.status === 'active' ? 'bg-red-900 text-red-100' :
              site.status === 'monitoring' ? 'bg-yellow-800 text-yellow-100' :
              'bg-green-900 text-green-100'
            }`}>
              {site.status.charAt(0).toUpperCase() + site.status.slice(1)}
            </span>
            <span className="px-2 py-1 bg-dark-cyan text-white text-xs rounded">
              {site.similarity_score.toFixed(1)}% Similar
            </span>
            <span className="px-2 py-1 bg-gray-800 text-gray-300 text-xs rounded">
              Target: {site.target_page.charAt(0).toUpperCase() + site.target_page.slice(1).replace('-', ' ')}
            </span>
            <span className="px-2 py-1 bg-gray-800 text-gray-300 text-xs rounded">
              Detected: {new Date(site.first_detected).toLocaleDateString()}
            </span>
          </div>
        </div>
        
        {/* Tabs */}
        <div className="flex border-b border-gray-800 mb-6">
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === 'overview'
                ? 'text-dark-cyan border-b-2 border-dark-cyan'
                : 'text-gray-400 hover:text-gray-300'
            }`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === 'technical'
                ? 'text-dark-cyan border-b-2 border-dark-cyan'
                : 'text-gray-400 hover:text-gray-300'
            }`}
            onClick={() => setActiveTab('technical')}
          >
            Technical Details
          </button>
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === 'content'
                ? 'text-dark-cyan border-b-2 border-dark-cyan'
                : 'text-gray-400 hover:text-gray-300'
            }`}
            onClick={() => setActiveTab('content')}
          >
            Content Analysis
          </button>
        </div>
        
        {/* Tab Content */}
        <div className="mb-6">
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="text-dark-cyan font-medium mb-2">Similarity Scores</h4>
                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-400">Overall Similarity</span>
                      <span className="text-white">{site.similarity_score.toFixed(1)}%</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-3">
                      <div 
                        className="bg-dark-cyan h-3 rounded-full" 
                        style={{ width: `${site.similarity_score}%` }}
                      ></div>
                    </div>
                  </div>
                  
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-400">Visual Similarity</span>
                      <span className="text-white">{site.visual_similarity?.toFixed(1) || 0}%</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-3">
                      <div 
                        className="bg-dark-cyan h-3 rounded-full" 
                        style={{ width: `${site.visual_similarity || 0}%` }}
                      ></div>
                    </div>
                  </div>
                  
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-400">Content Similarity</span>
                      <span className="text-white">{site.content_similarity?.toFixed(1) || 0}%</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-3">
                      <div 
                        className="bg-dark-cyan h-3 rounded-full" 
                        style={{ width: `${site.content_similarity || 0}%` }}
                      ></div>
                    </div>
                  </div>
                  
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-400">URL Similarity</span>
                      <span className="text-white">{site.url_similarity?.toFixed(1) || 0}%</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-3">
                      <div 
                        className="bg-dark-cyan h-3 rounded-full" 
                        style={{ width: `${site.url_similarity || 0}%` }}
                      ></div>
                    </div>
                  </div>
                  
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-400">ML Confidence</span>
                      <span className="text-white">{site.ml_confidence ? (site.ml_confidence * 100).toFixed(1) : 0}%</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-3">
                      <div 
                        className="bg-dark-cyan h-3 rounded-full" 
                        style={{ width: `${site.ml_confidence ? site.ml_confidence * 100 : 0}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
                
                <h4 className="text-dark-cyan font-medium mb-2 mt-6">Detected Features</h4>
                <div className="flex flex-wrap gap-2">
                  {site.features_detected.map((feature, idx) => (
                    <span key={idx} className="px-2 py-1 bg-gray-800 text-gray-300 text-xs rounded">
                      {feature.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                    </span>
                  ))}
                </div>
              </div>
              
              <div>
                <h4 className="text-dark-cyan font-medium mb-2">Screenshot</h4>
                <div className="bg-gray-800 rounded-lg border border-gray-700 p-2">
                  <div className="aspect-video bg-gray-700 rounded flex items-center justify-center mb-2">
                    {site.screenshot_path ? (
                      <img 
                        src={`/api/phishing/screenshot/${site.id}`} 
                        alt="Phishing site screenshot" 
                        className="w-full h-full object-cover rounded"
                      />
                    ) : (
                      <div className="text-gray-500 text-sm">Screenshot not available</div>
                    )}
                  </div>
                  <div className="flex space-x-2">
                    <button 
                      onClick={() => window.open(`/api/phishing/screenshot/${site.id}`, '_blank')}
                      className="flex-1 bg-dark-cyan text-white py-1 px-2 rounded text-sm"
                      disabled={!site.screenshot_path}
                    >
                      View Full
                    </button>
                    <button 
                      className="flex-1 bg-gray-700 text-white py-1 px-2 rounded text-sm"
                      onClick={() => window.open(`/api/phishing/compare/${site.id}`, '_blank')}
                      disabled={!site.screenshot_path}
                    >
                      Compare with Target
                    </button>
                  </div>
                </div>
                
                <div className="mt-6 space-y-3">
                  <button 
                    onClick={reportSite}
                    className="w-full bg-red-900 hover:bg-red-800 text-white py-2 px-4 rounded text-sm flex items-center justify-center"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                    Report Site
                  </button>
                  
                  {site.status !== 'taken-down' ? (
                    <button 
                      onClick={() => updateSiteStatus('taken-down')}
                      className="w-full bg-green-900 hover:bg-green-800 text-white py-2 px-4 rounded text-sm flex items-center justify-center"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                      Mark as Mitigated
                    </button>
                  ) : (
                    <button 
                      onClick={() => updateSiteStatus('active')}
                      className="w-full bg-gray-800 hover:bg-gray-700 text-white py-2 px-4 rounded text-sm flex items-center justify-center"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                      Mark as Active
                    </button>
                  )}
                  
                  <button 
                    className="w-full bg-gray-800 hover:bg-gray-700 text-white py-2 px-4 rounded text-sm flex items-center justify-center"
                    onClick={() => {
                      const confirmed = window.confirm(`Are you sure you want to block domain ${site.domain}?`);
                      if (confirmed) {
                        // In a real implementation, this would call an API to block the domain
                        alert(`Domain ${site.domain} has been added to block list`);
                      }
                    }}
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                      <path d="M4 3a2 2 0 100 4h12a2 2 0 100-4H4z" />
                      <path fillRule="evenodd" d="M3 8h14v7a2 2 0 01-2 2H5a2 2 0 01-2-2V8zm5 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" clipRule="evenodd" />
                    </svg>
                    Block Domain
                  </button>
                </div>
              </div>
            </div>
          )}
          
          {activeTab === 'technical' && (
            <div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-dark-cyan font-medium mb-3">Domain Information</h4>
                  <div className="bg-gray-800 rounded-lg p-4">
                    <div className="grid grid-cols-3 gap-y-3">
                      <div className="col-span-1 text-gray-400">Domain</div>
                      <div className="col-span-2 text-white">{site.domain}</div>
                      
                      <div className="col-span-1 text-gray-400">IP Address</div>
                      <div className="col-span-2 text-white">{site.ip_address || 'Unknown'}</div>
                      
                      <div className="col-span-1 text-gray-400">Country</div>
                      <div className="col-span-2 text-white">{site.country_code || 'Unknown'}</div>
                      
                      <div className="col-span-1 text-gray-400">Hosting</div>
                      <div className="col-span-2 text-white">{site.hosting_provider || 'Unknown'}</div>
                      
                      <div className="col-span-1 text-gray-400">Registrar</div>
                      <div className="col-span-2 text-white">{site.registrar || 'Unknown'}</div>
                      
                      <div className="col-span-1 text-gray-400">Registered</div>
                      <div className="col-span-2 text-white">
                        {site.registration_date 
                          ? new Date(site.registration_date).toLocaleDateString() 
                          : 'Unknown'}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-dark-cyan font-medium mb-3">Detection Information</h4>
                  <div className="bg-gray-800 rounded-lg p-4">
                    <div className="grid grid-cols-3 gap-y-3">
                      <div className="col-span-1 text-gray-400">First Detected</div>
                      <div className="col-span-2 text-white">
                        {new Date(site.first_detected).toLocaleString()}
                      </div>
                      
                      <div className="col-span-1 text-gray-400">Last Checked</div>
                      <div className="col-span-2 text-white">
                        {new Date(site.last_checked).toLocaleString()}
                      </div>
                      
                      <div className="col-span-1 text-gray-400">Status</div>
                      <div className="col-span-2 text-white capitalize">{site.status}</div>
                      
                      <div className="col-span-1 text-gray-400">Target Page</div>
                      <div className="col-span-2 text-white capitalize">
                        {site.target_page.replace('-', ' ')}
                      </div>
                      
                      <div className="col-span-1 text-gray-400">Has Login Form</div>
                      <div className="col-span-2 text-white">
                        {site.has_login_form ? 'Yes' : 'No'}
                      </div>
                      
                      <div className="col-span-1 text-gray-400">Has Logo</div>
                      <div className="col-span-2 text-white">
                        {site.has_tamm_logo ? 'Yes' : 'No'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              {site.form_targets && site.form_targets.length > 0 && (
                <div className="mt-6">
                  <h4 className="text-dark-cyan font-medium mb-3">Form Submission Targets</h4>
                  <div className="bg-gray-800 rounded-lg p-4">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left border-b border-gray-700">
                          <th className="pb-2 text-gray-400">Action</th>
                          <th className="pb-2 text-gray-400">Method</th>
                        </tr>
                      </thead>
                      <tbody>
                        {site.form_targets.map((form, idx) => (
                          <tr key={idx} className="border-b border-gray-700 last:border-0">
                            <td className="py-2 text-white">{form.action || 'self'}</td>
                            <td className="py-2 text-white">{form.method}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
          
          {activeTab === 'content' && (
            <div>
              <div className="flex flex-col md:flex-row gap-6">
                <div className="flex-1">
                  <h4 className="text-dark-cyan font-medium mb-3">HTML Content Preview</h4>
                  <div className="bg-gray-800 rounded-lg p-4 max-h-96 overflow-auto">
                    <pre className="text-xs text-gray-300 whitespace-pre-wrap">
                      {site.html_content 
                        ? site.html_content.substring(0, 5000) + (site.html_content.length > 5000 ? '...' : '')
                        : 'No HTML content available'}
                    </pre>
                  </div>
                </div>
              </div>
              
              <div className="mt-6">
                <h4 className="text-dark-cyan font-medium mb-3">Source Code Analysis</h4>
                <div className="bg-gray-800 rounded-lg p-4">
                  <p className="text-gray-300 text-sm mb-3">
                    This section analyzes the HTML source code for phishing indicators and suspicious elements.
                  </p>
                  
                  <div className="space-y-3">
                    <div>
                      <div className="text-gray-400 text-sm mb-1">Login Form Detection</div>
                      <div className="flex items-center">
                        <div className={`w-4 h-4 rounded-full mr-2 ${site.has_login_form ? 'bg-red-500' : 'bg-gray-500'}`}></div>
                        <span className="text-white">{site.has_login_form ? 'Login form detected' : 'No login form detected'}</span>
                      </div>
                    </div>
                    
                    <div>
                      <div className="text-gray-400 text-sm mb-1">Logo Detection</div>
                      <div className="flex items-center">
                        <div className={`w-4 h-4 rounded-full mr-2 ${site.has_tamm_logo ? 'bg-red-500' : 'bg-gray-500'}`}></div>
                        <span className="text-white">{site.has_tamm_logo ? 'Tamm logo detected' : 'No Tamm logo detected'}</span>
                      </div>
                    </div>
                    
                    <div>
                      <div className="text-gray-400 text-sm mb-1">SSL Certificate</div>
                      <div className="flex items-center">
                        <div className={`w-4 h-4 rounded-full mr-2 ${site.url.startsWith('https') ? 'bg-green-500' : 'bg-red-500'}`}></div>
                        <span className="text-white">{site.url.startsWith('https') ? 'HTTPS enabled' : 'No HTTPS'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
};

export default PhishingDetail;
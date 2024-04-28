import React, { useState, useEffect } from 'react';
import requests from './requests'; // Import the requests library

function ScanModal({ isOpen, onClose, scanType, target, onScanComplete }) {
  const [isLoading, setIsLoading] = useState(false);
  const [scanResult, setScanResult] = useState('');

  useEffect(() => {
    if (isOpen) {
      // Perform the scan when the modal is opened
      performScan(scanType, target);
    }
  }, [isOpen, scanType, target]);


  const performScan = async (scanType, target) => {
    setIsLoading(true);
    try {
      const response = await requests.post('http://localhost:4000/nmap', { scanType, target });
      setScanResult(response); // Set scanResult to the response string
      onScanComplete(); // Notify parent component about scan completion
    } catch (error) {
      console.error('Error performing scan:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`modal ${isOpen ? 'show' : ''}`} style={{ display: isOpen ? 'block' : 'none' }} tabIndex="-1">
      {/* Modal content */}
      <div className="modal-dialog modal-dialog-centered modal-dialog-scrollable">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">New Scan</h5>
            <button type="button" className="btn-close" onClick={onClose}></button>
          </div>
          <div className="modal-body" style={{ overflowY: 'auto' }}>
            {isLoading ? (
              <p>Loading...</p>
            ) : (
              <div>
                <p>Scan Result:</p>
                <div>
                  {scanResult.split('\n').map((line, index) => (
                    <pre key={index}>{line}</pre>
                  ))}
                </div>
              </div>
            )}
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ScanModal;
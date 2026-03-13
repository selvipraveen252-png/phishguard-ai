import React, { useState, useEffect } from 'react';

const SCAN_STEPS = [
  "Initializing Scan Engine",
  "Checking Domain Availability",
  "Verifying SSL Certificate",
  "Accessing Google Safe Browsing API",
  "Querying VirusTotal Threat Intelligence",
  "Retrieving IP Reputation Data (IPinfo)",
  "Running Phishing Heuristic Analysis",
  "Calculating Threat Score",
  "Generating Security Report"
];

const ScanProgress = ({ isScanning }) => {
  const [visibleSteps, setVisibleSteps] = useState(0);

  useEffect(() => {
    if (!isScanning) {
      setVisibleSteps(0);
      return;
    }

    const interval = setInterval(() => {
      setVisibleSteps(prev => {
        if (prev < SCAN_STEPS.length) {
          return prev + 1;
        }
        return prev;
      });
    }, 1200);

    return () => clearInterval(interval);
  }, [isScanning]);

  const progress = Math.min(Math.round((visibleSteps / SCAN_STEPS.length) * 100), 100);

  return (
    <div className="soc-card p-8 animate-fade-in max-w-2xl mx-auto border-t-2 border-t-cyber-cyan shadow-lg shadow-cyber-cyan/10 my-8">
      <div className="flex justify-between items-end mb-6">
        <div>
          <h3 className="text-xl font-bold text-white tracking-widest mb-1 italic font-mono">[ SCAN PROGRESS ]</h3>
          <p className="text-gray-500 font-mono text-[10px] uppercase tracking-widest">
            AI ENGINE IS ANALYZING THREAT VECTORS...
          </p>
        </div>
        <div className="text-right">
          <span className="text-cyber-cyan font-mono text-2xl font-bold">{progress}%</span>
        </div>
      </div>

      <div className="space-y-4 mb-10">
        {SCAN_STEPS.map((step, index) => {
          // If the step is index < (visibleSteps - 1), it's "Done"
          // If the step is index === (visibleSteps - 1) OR index === (visibleSteps), it's "In Progress" (spinners)
          // Actually let's just make it simple: 
          // Previous steps are done. Current step is spinning. Next steps are hidden.
          
          if (index >= visibleSteps) return null;

          const isCompleted = index < visibleSteps - 1;
          const isLastInList = index === visibleSteps - 1;

          return (
            <div 
              key={index} 
              className={`flex items-center gap-4 animate-slide-up transition-all duration-500`}
              style={{ animationDelay: '0s' }}
            >
              <div className="w-6 flex justify-center">
                {isCompleted ? (
                  <span className="text-cyber-green text-lg font-bold">✔</span>
                ) : (
                  <div className="w-4 h-4 border-2 border-cyber-cyan border-t-transparent rounded-full animate-spin"></div>
                )}
              </div>
              <span className={`font-mono text-sm tracking-wide ${isCompleted ? 'text-gray-400' : 'text-cyber-cyan shadow-cyber-cyan/20 font-bold'}`}>
                {step}
              </span>
            </div>
          );
        })}
      </div>

      <div className="relative pt-1">
        <div className="overflow-hidden h-2 mb-4 text-xs flex rounded bg-gray-800">
          <div 
            style={{ width: `${progress}%` }} 
            className="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-cyber-cyan transition-all duration-700 ease-out shadow-[0_0_15px_rgba(6,182,212,0.4)]"
          ></div>
        </div>
      </div>
    </div>
  );
};

export default ScanProgress;

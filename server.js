const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

const REPORTS_DIR = path.join(__dirname, 'reports');

// Ensure reports directory exists once on startup, rather than on every request
fs.mkdirSync(REPORTS_DIR, { recursive: true });

app.post('/scan', (req, res) => {
  let { target, use_nmap, use_subdomains, use_ports } = req.body;

  if (!target) return res.status(400).json({ error: 'Target is required' });
  
  // Basic format validation
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
  }

  const payload = JSON.stringify({ target, use_nmap, use_subdomains, use_ports });

  // Handle OS differences for the virtual environment
  const pythonExe = process.platform === 'win32' 
    ? '.venv\\Scripts\\python' 
    : './.venv/bin/python';

  const python = spawn(pythonExe, [
    path.join(__dirname, 'runner.py'),
    payload
  ]);

  let output = '';
  let errorOutput = '';

  python.stdout.on('data', (data) => { output += data.toString(); });
  python.stderr.on('data', (data) => { errorOutput += data.toString(); });

  // Prevent server crashes if Python fails to spawn
  python.on('error', (err) => {
    console.error('Subprocess error:', err);
    if (!res.headersSent) res.status(500).json({ error: 'Failed to start the scanner' });
  });

  python.on('close', (code) => {
    if (res.headersSent) return;
    
    if (code !== 0) {
      console.error('Scan Error Output:', errorOutput);
      return res.status(500).json({ error: 'Scan failed or cancelled' });
    }
    
    try {
      const parsed = JSON.parse(output);
      
      // FALLBACK logic: Ideally, python should pass back the exact filename in 'parsed.report_file'
      let reportFile = parsed.report_file; 
      
      if (!reportFile) {
        const files = fs.readdirSync(REPORTS_DIR)
          .filter(f => f.endsWith('.html'))
          .map(f => ({ name: f, time: fs.statSync(path.join(REPORTS_DIR, f)).mtimeMs }))
          .sort((a, b) => b.time - a.time);
        reportFile = files.length > 0 ? files[0].name : null;
      }

      res.json({ ...parsed.results, report_file: reportFile });
    } catch (e) {
      console.error('Failed to parse Python output:', e, '\nRaw output:', output);
      res.status(500).json({ error: 'Failed to parse scan results' });
    }
  });
});

app.get('/reports', (req, res) => {
  try {
    const files = fs.readdirSync(REPORTS_DIR).filter(f => f.endsWith('.html')).sort().reverse();
    res.json(files);
  } catch (e) {
    res.status(500).json({ error: 'Failed to retrieve reports list' });
  }
});

app.get('/reports/:filename', (req, res) => {
  const { filename } = req.params;

  // Prevent Path Traversal by blocking directory navigation characters
  if (filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  // Use the root option for safe file serving
  res.sendFile(filename, { root: REPORTS_DIR }, (err) => {
    if (err) {
      res.status(404).json({ error: 'Report not found' });
    }
  });
});

app.listen(5000, () => console.log('Scanner API running on port 5000'));
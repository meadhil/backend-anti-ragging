const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');

const commonMalwarePatterns = [
  /javascript:/i,
  /vbscript:/i,
  /<script.*?>/i,
  /eval\(/i,
  /document\.write\(/i,
  /base64,/i,
  /powershell/i,
  /mshta/i,
  /wscript/i,
  /cscript/i,
  /<iframe/i,
  /onerror=/i,
  /onload=/i,
];

const checkCommonPatterns = (fileBuffer) => {
  const content = fileBuffer.toString('utf8');
  return commonMalwarePatterns.some(pattern => pattern.test(content));
};

const scanFile = async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const fileBuffer = fs.readFileSync(req.file.path);
  const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  try {
    // Step 1: Fast Pattern Check
    const suspicious = checkCommonPatterns(fileBuffer);
    if (suspicious) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'File contains suspicious patterns. Upload rejected.' });
    }

    // Step 2: VirusTotal Scan
    const response = await axios.get(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
    });

    const analysis = response.data.data.attributes.last_analysis_stats;
    const malicious = analysis.malicious || 0;

    if (malicious > 0) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'File is malicious according to VirusTotal.' });
    }

    req.scanResult = {
      fileHash,
      scanStatus: 'clean',
      virusTotalLink: `https://www.virustotal.com/gui/file/${fileHash}`,
    };
    next();
  } catch (error) {
    console.error(error.response?.data || error.message);
    return res.status(500).json({ error: 'Virus scan failed' });
  }
};

module.exports = scanFile;

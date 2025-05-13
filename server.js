require('dotenv').config();
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const MONGO_URI = process.env.MONGO_URI;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const upload = multer({ dest: 'uploads/' });

// ====================== MongoDB Setup ======================

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection failed:', err));

// ====================== Models ======================

const userSchema = new mongoose.Schema({
  name: String,
  department: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
}, { toJSON: { virtuals: true } });

userSchema.virtual('isAdmin').get(function () {
  return this.role === 'admin';
});

const User = mongoose.model('User', userSchema);

const complaintSchema = new mongoose.Schema({
  subject: String,
  description: String,
  date: String,
  location: String,
  witnesses: String,
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  filePath: String,
}, { timestamps: true });

const Complaint = mongoose.model('Complaint', complaintSchema);

const scanReportSchema = new mongoose.Schema({
  fileHash: { type: String, required: true },
  status: { type: String, enum: ['clean', 'malicious'], required: true },
  vtLink: String,
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  originalFilename: String,
}, { timestamps: true });

// Remove the unique index from fileHash or user_id combination
// If you previously added a compound unique index, it will be removed now
scanReportSchema.index({ fileHash: 1, user_id: 1 }, { unique: false });

const ScanReport = mongoose.model('ScanReport', scanReportSchema);


// ====================== JWT Middleware ======================

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token' });
  }
};

// ====================== VirusTotal Logic ======================

function calculateHash(filePath) {
  const buffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function queryVirusTotal(fileHash) {
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
      headers: { 'x-apikey': VT_API_KEY },
    });
    return response.data;
  } catch (err) {
    console.error('❌ VT query error:', err.message);
    return null;
  }
}

async function uploadToVirusTotal(filePath) {
  const formData = new FormData();
  formData.append('file', fs.createReadStream(filePath));

  try {
    const response = await axios.post(`https://www.virustotal.com/api/v3/files`, formData, {
      headers: {
        ...formData.getHeaders(),
        'x-apikey': VT_API_KEY,
      },
    });
    return response.data;
  } catch (err) {
    console.error('❌ VT upload error:', err.message);
    return null;
  }
}

// ====================== Auth Routes ======================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, department, email, password } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await new User({ name, department, email, password: hashedPassword }).save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isAdmin: user.role === 'admin'
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ====================== Complaint Route ======================
app.post('/api/complaints/submit', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { subject, description, date, location, witnesses } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ message: 'File is required' });

    const filePath = file.path;
    const fileHash = calculateHash(filePath);

    let scanReport = null;
    let status, vtLink;

    // Query VirusTotal for a scan report
    let result = await queryVirusTotal(fileHash);

    if (!result) {
      const uploadResult = await uploadToVirusTotal(filePath);
      if (!uploadResult?.data?.id) {
        fs.unlinkSync(filePath);
        return res.status(500).json({ message: 'VirusTotal upload failed' });
      }
      const scanId = uploadResult.data.id;
      await new Promise(r => setTimeout(r, 15000)); // Wait for scan
      result = await queryVirusTotal(scanId);
    }

    if (!result) return res.status(500).json({ message: 'Virus scan failed' });

    const stats = result.data.attributes.last_analysis_stats;
    status = stats.malicious > 0 ? 'malicious' : 'clean';
    vtLink = `https://www.virustotal.com/gui/file/${fileHash}`;

    // Save scan report with user_id for tracking multiple entries for the same file
    scanReport = await new ScanReport({
      fileHash,
      status,
      vtLink,
      user_id: req.user.userId,  // Associate the report with the logged-in user
      originalFilename: file.originalname
    }).save();

    // Save complaint
    const complaint = await new Complaint({
      subject, description, date, location, witnesses,
      user_id: req.user.userId, filePath,
    }).save();

    res.json({ success: true, message: 'Complaint submitted', filename: file.originalname, status, vtLink });
  } catch (err) {
    console.error('❌ Submission error:', err);
    res.status(500).json({ message: 'Error submitting complaint' });
  } finally {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
  }
});


// ====================== Admin Routes ======================

app.get('/api/complaints/all', authenticateToken, async (req, res) => {
  try {
    const complaints = await Complaint.find().populate('user_id', 'name department');
    const formatted = complaints.map(c => ({
      _id: c._id, subject: c.subject, description: c.description, date: c.date,
      location: c.location, witnesses: c.witnesses, filePath: c.filePath,
      name: c.user_id?.name || 'Unknown', department: c.user_id?.department || 'Unknown',
      createdAt: c.createdAt, updatedAt: c.updatedAt,
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching complaints' });
  }
});

app.get('/api/scans/all', authenticateToken, async (req, res) => {
  try {
    const scans = await ScanReport.find().populate('user_id', 'name department');
    const formatted = scans.map(s => ({
      _id: s._id, originalFilename: s.originalFilename, fileHash: s.fileHash,
      status: s.status, vtLink: s.vtLink,
      name: s.user_id?.name || 'Unknown', department: s.user_id?.department || 'Unknown',
      createdAt: s.createdAt
    }));
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching scan reports' });
  }
});

// ====================== Start Server ======================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

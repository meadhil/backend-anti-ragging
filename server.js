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

// ============ MongoDB Setup ============

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection failed:', err));

// ============ Models ============

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  department: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
});

userSchema.virtual('isAdmin').get(function () {
  return this.role === 'admin';
});

userSchema.set('toJSON', { virtuals: true });

const User = mongoose.model('User', userSchema);

const complaintSchema = new mongoose.Schema({
  subject: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: String },
  location: { type: String },
  witnesses: { type: String },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  filePath: { type: String },
}, { timestamps: true });

const Complaint = mongoose.model('Complaint', complaintSchema);

// Create a model for the scan reports
const scanReportSchema = new mongoose.Schema({
  fileHash: { type: String, required: true, unique: true },
  status: { type: String, enum: ['clean', 'malicious'], required: true },
  vtLink: { type: String, required: true },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Optional if associated with a user
  originalFilename: { type: String, required: true },
}, { timestamps: true });

const ScanReport = mongoose.model('ScanReport', scanReportSchema);

// ============ JWT Middleware ============

const authenticateToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  console.log('🔐 Incoming Auth Header:', authHeader);

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token' });
  }
};

// ============ Hashing and VirusTotal Functions ============

function calculateHash(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

async function queryVirusTotal(fileHash) {
  const url = `https://www.virustotal.com/api/v3/files/${fileHash}`;
  try {
    const response = await axios.get(url, { headers: { 'x-apikey': VT_API_KEY } });

    // Check if the response is valid and contains the expected data
    if (!response || !response.data) {
      throw new Error('Invalid response from VirusTotal');
    }

    return response.data;  // Return the data if valid
  } catch (err) {
    console.error('❌ Error querying VirusTotal:', err.message);
    return null;  // Return null if the request fails or an error occurs
  }
}

async function uploadToVirusTotal(filePath) {
  const url = `https://www.virustotal.com/api/v3/files`;
  const formData = new FormData();
  formData.append('file', fs.createReadStream(filePath));

  try {
    const response = await axios.post(url, formData, {
      headers: {
        ...formData.getHeaders(),
        'x-apikey': VT_API_KEY,
      },
    });
    return response.data;
  } catch (err) {
    console.error('❌ Error uploading to VirusTotal:', err.message);
    return null;  // Return null if the upload fails
  }
}

// ============ Auth Routes ============

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, department, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, department, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
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

  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ============ Complaint Routes ============

app.post('/api/complaints/submit', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { subject, description, date, location, witnesses } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ message: 'File is required' });

    const filePath = file.path;
    const fileHash = calculateHash(filePath);

    // Check if the file has been scanned already
    const existingScanReport = await ScanReport.findOne({ fileHash });
    if (existingScanReport) {
      // If it exists, return the existing scan result
      return res.json({
        success: true,
        message: 'File already scanned',
        filename: file.originalname,
        status: existingScanReport.status,
        vtLink: existingScanReport.vtLink,
      });
    }

    let result = await queryVirusTotal(fileHash);

    // Handle case where queryVirusTotal returns null
    if (!result) {
      const uploadResult = await uploadToVirusTotal(filePath);
      if (!uploadResult || !uploadResult.data || !uploadResult.data.id) {
        fs.unlinkSync(filePath);
        return res.status(500).json({ message: 'VirusTotal upload failed' });
      }
      const scanId = uploadResult.data.id;
      await new Promise(r => setTimeout(r, 15000));  // Wait for 15 seconds
      result = await queryVirusTotal(scanId);
    }

    // If result is still null, return an error
    if (!result) {
      return res.status(500).json({ message: 'Virus scan failed or no result found' });
    }

    const stats = result.data.attributes.last_analysis_stats;
    const status = stats.malicious > 0 ? 'malicious' : 'clean';
    const vtLink = `https://www.virustotal.com/gui/file/${fileHash}`;

    // Save the scan report in the ScanReport collection
    const scanReport = new ScanReport({
      fileHash,
      status,
      vtLink,
      user_id: req.user.userId,  // Optional if linked to a user
      originalFilename: file.originalname, // Store the filename
    });

    await scanReport.save();

    const newComplaint = new Complaint({
      subject,
      description,
      date,
      location,
      witnesses,
      user_id: req.user.userId,
      filePath,
    });
    await newComplaint.save();

    res.json({
      success: true,
      message: 'Complaint submitted successfully',
      filename: file.originalname,
      status,
      vtLink,
    });
  } catch (err) {
    console.error('❌ Error:', err);
    res.status(500).json({ message: 'Server error during complaint submission' });
  } finally {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
  }
});

app.get('/api/complaints/all', authenticateToken, async (req, res) => {
  try {
    const complaints = await Complaint.find()
      .populate({ path: 'user_id', select: 'name department' });

    const formatted = complaints.map(c => ({
      _id: c._id,
      subject: c.subject,
      description: c.description,
      date: c.date,
      location: c.location,
      witnesses: c.witnesses,
      filePath: c.filePath,
      name: c.user_id?.name || 'Unknown',
      department: c.user_id?.department || 'Unknown',
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
    }));

    res.status(200).json(formatted);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching complaints' });
  }
});
// ============ Scan Report Route ============
app.get('/api/scans/all', authenticateToken, async (req, res) => {
  try {
    const scans = await ScanReport.find().populate({ path: 'user_id', select: 'name department' });

    const formatted = scans.map(s => ({
      _id: s._id,
      originalFilename: s.originalFilename,
      fileHash: s.fileHash,
      status: s.status,
      vtLink: s.vtLink,
      name: s.user_id?.name || 'Unknown',
      department: s.user_id?.department || 'Unknown',
      createdAt: s.createdAt,
    }));

    res.status(200).json(formatted);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching scan reports' });
  }
});



// ============ Start Server ============

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

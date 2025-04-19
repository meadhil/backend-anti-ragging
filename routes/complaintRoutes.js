const express = require('express');
const router = express.Router();
const { submitComplaint, getComplaints } = require('../controllers/complaintController');
const authMiddleware = require('../middlewares/authMiddleware');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // Handle file uploads

router.post('/submit-complaint', authMiddleware, upload.single('file'), submitComplaint);
router.get('/complaint', authMiddleware, getComplaints);

module.exports = router;
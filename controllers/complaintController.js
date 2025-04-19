const Complaint = require('../models/Complaint');

exports.submitComplaint = async (req, res) => {
  try {
    const { subject, description, date, location, witnesses, user_id } = req.body;

    const newComplaint = new Complaint({
      subject,
      description,
      date,
      location,
      witnesses,
      user_id,
      filePath: req.file ? req.file.path : null, // Handle file path if uploaded
    });

    await newComplaint.save();
    res.status(201).json({ success: true, message: 'Complaint submitted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.getComplaints = async (req, res) => {
  try {
    // Admin should see all complaints
    const complaints = await Complaint.find(); // No user_id filter here
    
    res.status(200).json(complaints);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
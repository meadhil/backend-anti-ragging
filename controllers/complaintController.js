const Complaint = require('../models/complaint');
const User = require('../models/user'); // Import the User model

exports.submitComplaint = async (req, res) => {
  try {
    const { subject, description, date, location, witnesses, user_id } = req.body;

    const newComplaint = new Complaint({
      subject,
      description,
      date,
      location,
      witnesses,
      user_id, // Reference to the User collection
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
    const complaints = await Complaint.find()
      .populate({
        path: 'user_id',
        select: 'name department',
      });

    // Map and adjust the response
    const formattedComplaints = complaints.map((complaint) => ({
      _id: complaint._id,
      subject: complaint.subject,
      description: complaint.description,
      date: complaint.date,
      location: complaint.location,
      witnesses: complaint.witnesses,
      filePath: complaint.filePath,
      status: complaint.status,
      name: complaint.user_id?.name || 'Unknown',
      department: complaint.user_id?.department || 'Unknown',
      createdAt: complaint.createdAt,
      updatedAt: complaint.updatedAt,
    }));

    res.status(200).json(formattedComplaints);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

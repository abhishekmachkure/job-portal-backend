require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

/* ================== MIDDLEWARE ================== */
app.use(express.json());
app.use(cors({ origin: "*" }));

/* ================== MONGODB ================== */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ DB Error:", err));

/* ================== MODELS ================== */

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user"
  },
  skills: [String],
  education: String,
  resume: String,
  phone: String,
  location: String,
  linkedin: String
});

const JobSchema = new mongoose.Schema({
  title: String,
  company: String,
  location: String,
  salary: String,
  skills: String
});

const ApplicationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  job: { type: mongoose.Schema.Types.ObjectId, ref: "Job" },
  status: {
    type: String,
    enum: ["applied", "accepted", "rejected"],
    default: "applied"
  }
});

const User = mongoose.model("User", UserSchema);
const Job = mongoose.model("Job", JobSchema);
const Application = mongoose.model("Application", ApplicationSchema);

/* ================== AUTH ================== */

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only ❌" });
  }
  next();
};

/* ================== HEALTH CHECK ================== */
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

/* ================== AUTH ROUTES ================== */

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: "User exists" });

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({ name, email, password: hashed });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, role: user.role });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const match = await bcrypt.compare(req.body.password, user.password);
    if (!match) return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, role: user.role });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ================== JOB ROUTES ================== */

// GET ALL JOBS
app.get("/api/jobs", async (req, res) => {
  const jobs = await Job.find();
  res.json(jobs);
});

// GET SINGLE JOB
app.get("/api/jobs/:id", async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);

    if (!job) {
      return res.status(404).json({ message: "Job not found" });
    }

    res.json(job);

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// CREATE JOB
app.post("/api/jobs", auth, adminOnly, async (req, res) => {
  const job = await Job.create(req.body);
  res.json(job);
});

// UPDATE JOB
app.put("/api/jobs/:id", auth, adminOnly, async (req, res) => {
  try {
    const updated = await Job.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ message: "Job not found" });
    }

    res.json(updated);

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE JOB
app.delete("/api/jobs/:id", auth, adminOnly, async (req, res) => {
  await Job.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

/* ================== APPLICATION ================== */

// APPLY
app.post("/api/apply", auth, async (req, res) => {
  const exists = await Application.findOne({
    user: req.user.id,
    job: req.body.jobId
  });

  if (exists) {
    return res.status(400).json({ message: "Already applied" });
  }

  const appData = await Application.create({
    user: req.user.id,
    job: req.body.jobId
  });

  res.json(appData);
});

// USER APPLICATIONS
app.get("/api/my-applications", auth, async (req, res) => {
  const apps = await Application.find({ user: req.user.id }).populate("job");
  res.json(apps);
});

// ADMIN APPLICATIONS
app.get("/api/applications", auth, adminOnly, async (req, res) => {
  try {
    const apps = await Application.find()
      .populate(
        "user",
        "name email skills education phone location linkedin resume"
      )
      .populate(
        "job",
        "title company location salary skills"
      );

    res.json(apps);

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE APPLICATION
app.delete("/api/applications/:id", auth, async (req, res) => {
  const application = await Application.findById(req.params.id);

  if (!application) {
    return res.status(404).json({ message: "Application not found" });
  }

  if (application.user.toString() !== req.user.id) {
    return res.status(403).json({ message: "Not allowed ❌" });
  }

  await Application.findByIdAndDelete(req.params.id);

  res.json({ message: "Application withdrawn ✅" });
});

/* ================= PROFILE ================= */

// GET PROFILE
app.get("/api/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});

// UPDATE PROFILE
app.put("/api/user/profile", auth, async (req, res) => {
  const updated = await User.findByIdAndUpdate(
    req.user.id,
    req.body,
    { new: true }
  ).select("-password");

  res.json(updated);
});

/* ================== SERVER ================== */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

const ApplicationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  job: { type: mongoose.Schema.Types.ObjectId, ref: "Job" },
  status: {
    type: String,
    enum: ["applied", "accepted", "rejected"],
    default: "applied"
  }
}, { timestamps: true }); // ✅ ADD THIS LINE
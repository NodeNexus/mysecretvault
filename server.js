const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
const MONGODB_URI = process.env.MONGODB_URI;

let db;
let usersCollection;
let notesCollection;
let sharedNotesCollection;
let sessionsCollection;

// Connect to MongoDB
async function connectDB() {
  try {
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is not set');
    }
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log('✅ Connected to MongoDB');
    
    db = client.db('vishreyuu-diary');
    usersCollection = db.collection('users');
    notesCollection = db.collection('notes');
    sharedNotesCollection = db.collection('sharedNotes');
    sessionsCollection = db.collection('sessions');
    
    // Create indexes for better performance
    await usersCollection.createIndex({ username: 1 }, { unique: true });
    await notesCollection.createIndex({ owner: 1 });
    await sharedNotesCollection.createIndex({ recipient: 1 });
    await sessionsCollection.createIndex({ username: 1 });
    await sessionsCollection.createIndex({ sessionId: 1 }, { unique: true });
    
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
}

connectDB();

// Encryption utilities
function encrypt(text, userKey) {
  const iv = crypto.randomBytes(16);
  const key = crypto.createHash('sha256').update(userKey + ENCRYPTION_KEY.toString('hex')).digest();
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text, userKey) {
  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = parts[1];
  const key = crypto.createHash('sha256').update(userKey + ENCRYPTION_KEY.toString('hex')).digest();
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Get device info from user agent
function getDeviceInfo(userAgent) {
  if (/mobile/i.test(userAgent)) return 'Mobile';
  if (/tablet/i.test(userAgent)) return 'Tablet';
  return 'Desktop';
}

function getBrowser(userAgent) {
  if (userAgent.includes('Chrome')) return 'Chrome';
  if (userAgent.includes('Firefox')) return 'Firefox';
  if (userAgent.includes('Safari')) return 'Safari';
  if (userAgent.includes('Edge')) return 'Edge';
  return 'Unknown';
}

// Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userKey = decoded.userKey;
    req.sessionId = decoded.sessionId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  
  try {
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const userKey = crypto.randomBytes(32).toString('hex');
    
    const user = {
      username,
      email: email || '',
      password: hashedPassword,
      userKey,
      createdAt: new Date(),
      lastLogin: null,
      profileColor: '#' + Math.floor(Math.random()*16777215).toString(16)
    };
    
    await usersCollection.insertOne(user);
    
    const sessionId = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ userId: username, userKey, sessionId }, JWT_SECRET);
    
    const userAgent = req.headers['user-agent'] || '';
    const session = {
      sessionId,
      username,
      device: getDeviceInfo(userAgent),
      browser: getBrowser(userAgent),
      loginTime: new Date(),
      lastActive: new Date(),
      ip: req.ip
    };
    
    await sessionsCollection.insertOne(session);
    
    res.json({ token, username, email: email || '' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await usersCollection.findOne({ username });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    await usersCollection.updateOne(
      { username },
      { $set: { lastLogin: new Date() } }
    );
    
    const sessionId = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign({ userId: username, userKey: user.userKey, sessionId }, JWT_SECRET);
    
    const userAgent = req.headers['user-agent'] || '';
    const session = {
      sessionId,
      username,
      device: getDeviceInfo(userAgent),
      browser: getBrowser(userAgent),
      loginTime: new Date(),
      lastActive: new Date(),
      ip: req.ip
    };
    
    await sessionsCollection.insertOne(session);
    
    res.json({ 
      token, 
      username,
      email: user.email || '',
      profileColor: user.profileColor
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/logout', auth, async (req, res) => {
  try {
    await sessionsCollection.deleteOne({ sessionId: req.sessionId });
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.get('/api/user/profile', auth, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ username: req.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const totalNotes = await notesCollection.countDocuments({ owner: req.userId });
    const sharedNotesCount = await sharedNotesCollection.countDocuments({ recipient: req.userId });
    
    res.json({
      username: user.username,
      email: user.email,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      profileColor: user.profileColor,
      totalNotes,
      sharedNotesCount
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.put('/api/user/profile', auth, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ username: req.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const { email, currentPassword, newPassword, profileColor } = req.body;
    
    const updateFields = {};
    
    if (email !== undefined) {
      updateFields.email = email;
    }
    
    if (profileColor) {
      updateFields.profileColor = profileColor;
    }
    
    if (currentPassword && newPassword) {
      if (!(await bcrypt.compare(currentPassword, user.password))) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      updateFields.password = await bcrypt.hash(newPassword, 10);
    }
    
    await usersCollection.updateOne(
      { username: req.userId },
      { $set: updateFields }
    );
    
    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.get('/api/user/sessions', auth, async (req, res) => {
  try {
    const userSessions = await sessionsCollection.find({ username: req.userId }).toArray();
    
    const sessions = userSessions.map(session => ({
      sessionId: session.sessionId,
      device: session.device,
      browser: session.browser,
      loginTime: session.loginTime,
      lastActive: session.lastActive,
      isCurrent: session.sessionId === req.sessionId
    }));
    
    res.json(sessions);
  } catch (err) {
    console.error('Get sessions error:', err);
    res.status(500).json({ error: 'Failed to load sessions' });
  }
});

app.delete('/api/user/sessions/:sessionId', auth, async (req, res) => {
  try {
    const session = await sessionsCollection.findOne({ sessionId: req.params.sessionId });
    
    if (!session || session.username !== req.userId) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    if (session.sessionId === req.sessionId) {
      return res.status(400).json({ error: 'Cannot terminate current session' });
    }
    
    await sessionsCollection.deleteOne({ sessionId: req.params.sessionId });
    res.json({ message: 'Session terminated' });
  } catch (err) {
    console.error('Delete session error:', err);
    res.status(500).json({ error: 'Failed to terminate session' });
  }
});

app.get('/api/user/login-history', auth, async (req, res) => {
  try {
    const history = await sessionsCollection
      .find({ username: req.userId })
      .sort({ loginTime: -1 })
      .limit(20)
      .toArray();
    
    const historyData = history.map(h => ({
      device: h.device,
      browser: h.browser,
      loginTime: h.loginTime,
      ip: h.ip
    }));
    
    res.json(historyData);
  } catch (err) {
    console.error('Get login history error:', err);
    res.status(500).json({ error: 'Failed to load login history' });
  }
});

app.get('/api/notes', auth, async (req, res) => {
  try {
    await sessionsCollection.updateOne(
      { sessionId: req.sessionId },
      { $set: { lastActive: new Date() } }
    );
    
    const userNotes = await notesCollection.find({ owner: req.userId }).toArray();
    
    const decryptedNotes = userNotes.map(note => ({
      id: note._id.toString(),
      title: decrypt(note.title, req.userKey),
      content: decrypt(note.content, req.userKey),
      color: note.color,
      tags: note.tags,
      createdAt: note.createdAt,
      updatedAt: note.updatedAt
    }));
    
    res.json(decryptedNotes);
  } catch (err) {
    console.error('Get notes error:', err);
    res.status(500).json({ error: 'Failed to load notes' });
  }
});

app.post('/api/notes', auth, async (req, res) => {
  const { title, content, color, tags } = req.body;
  
  try {
    const note = {
      owner: req.userId,
      title: encrypt(title, req.userKey),
      content: encrypt(content, req.userKey),
      color: color || '#6366f1',
      tags: tags || [],
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    const result = await notesCollection.insertOne(note);
    
    res.json({
      id: result.insertedId.toString(),
      title,
      content,
      color: note.color,
      tags: note.tags,
      createdAt: note.createdAt,
      updatedAt: note.updatedAt
    });
  } catch (err) {
    console.error('Create note error:', err);
    res.status(500).json({ error: 'Failed to create note' });
  }
});

app.put('/api/notes/:id', auth, async (req, res) => {
  try {
    const note = await notesCollection.findOne({ _id: new ObjectId(req.params.id) });
    
    if (!note || note.owner !== req.userId) {
      return res.status(404).json({ error: 'Note not found' });
    }
    
    const { title, content, color, tags } = req.body;
    
    await notesCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          title: encrypt(title, req.userKey),
          content: encrypt(content, req.userKey),
          color: color || note.color,
          tags: tags || note.tags,
          updatedAt: new Date()
        }
      }
    );
    
    res.json({
      id: req.params.id,
      title,
      content,
      color: color || note.color,
      tags: tags || note.tags,
      createdAt: note.createdAt,
      updatedAt: new Date()
    });
  } catch (err) {
    console.error('Update note error:', err);
    res.status(500).json({ error: 'Failed to update note' });
  }
});

app.delete('/api/notes/:id', auth, async (req, res) => {
  try {
    const result = await notesCollection.deleteOne({
      _id: new ObjectId(req.params.id),
      owner: req.userId
    });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Note not found' });
    }
    
    res.json({ message: 'Note deleted' });
  } catch (err) {
    console.error('Delete note error:', err);
    res.status(500).json({ error: 'Failed to delete note' });
  }
});

app.post('/api/notes/:id/share', auth, async (req, res) => {
  try {
    const note = await notesCollection.findOne({ _id: new ObjectId(req.params.id) });
    
    if (!note || note.owner !== req.userId) {
      return res.status(404).json({ error: 'Note not found' });
    }
    
    const { recipient, unlockDate } = req.body;
    
    const recipientUser = await usersCollection.findOne({ username: recipient });
    if (!recipientUser) {
      return res.status(404).json({ error: 'Recipient not found' });
    }
    
    const sharedNote = {
      noteId: req.params.id,
      owner: req.userId,
      recipient,
      title: encrypt(decrypt(note.title, req.userKey), recipientUser.userKey),
      content: encrypt(decrypt(note.content, req.userKey), recipientUser.userKey),
      color: note.color,
      unlockDate: new Date(unlockDate),
      sharedAt: new Date()
    };
    
    const result = await sharedNotesCollection.insertOne(sharedNote);
    
    res.json({ message: 'Note shared successfully', shareId: result.insertedId.toString() });
  } catch (err) {
    console.error('Share note error:', err);
    res.status(500).json({ error: 'Failed to share note' });
  }
});

app.get('/api/shared-notes', auth, async (req, res) => {
  try {
    const userSharedNotes = await sharedNotesCollection.find({ recipient: req.userId }).toArray();
    
    const notes = userSharedNotes.map(share => {
      const now = new Date();
      const unlocked = now >= share.unlockDate;
      
      return {
        id: share._id.toString(),
        title: unlocked ? decrypt(share.title, req.userKey) : 'Locked Note',
        content: unlocked ? decrypt(share.content, req.userKey) : 'This note will unlock on ' + share.unlockDate.toLocaleString(),
        color: share.color,
        unlockDate: share.unlockDate,
        unlocked,
        sharedBy: share.owner,
        sharedAt: share.sharedAt
      };
    });
    
    res.json(notes);
  } catch (err) {
    console.error('Get shared notes error:', err);
    res.status(500).json({ error: 'Failed to load shared notes' });
  }
});

app.get('/api/users/search', auth, async (req, res) => {
  try {
    const query = req.query.q?.toLowerCase() || '';
    const users = await usersCollection
      .find({ 
        username: { $regex: query, $options: 'i' },
        username: { $ne: req.userId }
      })
      .limit(10)
      .toArray();
    
    const usernames = users.map(u => u.username);
    res.json(usernames);
  } catch (err) {
    console.error('Search users error:', err);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vishreyuu's Diary running on port ${PORT}`);
});
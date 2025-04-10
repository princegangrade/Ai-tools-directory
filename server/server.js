// server/server.js
require('dotenv').config(); // LOAD ENV VARS FIRST!

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db'); // Your db module using pg
const authenticateToken = require('./middleware/auth'); // Import the JWT middleware

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;

// --- Middleware ---
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON bodies

// --- Helper --- Basic Email Validation (Example)
function isValidEmail(email) {
  if (!email) return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// --- API Routes ---

// Root endpoint
app.get('/', (req, res) => {
  res.send('AI Tools Directory API is running!');
});

// --- Tool Routes (Public) ---
app.get('/api/tools', async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 9;
  const offset = (page - 1) * limit;
  try {
    const toolsQuery = `
        SELECT t.id, t.name, t.slug, t.description, t.website_url, t.try_now_url, t.image_url, t.pricing_text, t.pricing_low, t.pricing_high, t.rating_avg, t.review_count, t.tags_array, t.features_json, c.name AS category_name, c.slug AS category_slug, t.created_at
        FROM tools t LEFT JOIN categories c ON t.category_id = c.id WHERE t.status = 'approved' ORDER BY t.id LIMIT $1 OFFSET $2;`;
    const result = await db.query(toolsQuery, [limit, offset]);
    const countResult = await db.query("SELECT COUNT(*) FROM tools WHERE status = 'approved'");
    const totalTools = parseInt(countResult.rows[0]?.count || '0', 10); // Safer parsing
    const totalPages = Math.ceil(totalTools / limit);
    // console.log(`API: Fetched ${result.rows.length} tools for page ${page}`);
    res.json({ tools: result.rows, pagination: { currentPage: page, totalPages: totalPages, totalTools: totalTools, limit: limit } });
  } catch (error) { console.error('Error fetching tools:', error); res.status(500).json({ error: 'Internal Server Error fetching tools' }); }
});

app.get('/api/tools/:slug', async (req, res) => {
  const { slug } = req.params;
  if (!slug) return res.status(400).json({ error: 'Tool slug is required.' });
  try {
    const query = `SELECT t.*, c.name AS category_name, c.slug AS category_slug FROM tools t LEFT JOIN categories c ON t.category_id = c.id WHERE t.slug = $1 AND t.status = 'approved';`;
    const result = await db.query(query, [slug]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tool not found' });
    res.json(result.rows[0]);
  } catch (error) { console.error(`Error fetching tool ${slug}:`, error); res.status(500).json({ error: 'Internal Server Error fetching tool' }); }
});

// --- News Routes (Public) ---
app.get('/api/news', async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 3;
  const offset = (page - 1) * limit;
  try {
    const query = `SELECT * FROM news_articles WHERE status = 'published' ORDER BY published_date DESC, created_at DESC LIMIT $1 OFFSET $2;`;
    const result = await db.query(query, [limit, offset]);
    const countResult = await db.query("SELECT COUNT(*) FROM news_articles WHERE status = 'published'");
    const totalNews = parseInt(countResult.rows[0]?.count || '0', 10); // Safer parsing
    const totalPages = Math.ceil(totalNews / limit);
    res.json({ news: result.rows, pagination: { currentPage: page, totalPages: totalPages, totalNews: totalNews, limit: limit } });
  } catch (error) { console.error('Error fetching news:', error); res.status(500).json({ error: 'Internal Server Error fetching news' }); }
});

app.get('/api/news/:slug', async (req, res) => {
  const { slug } = req.params;
   if (!slug) return res.status(400).json({ error: 'News slug is required.' });
  try {
    const query = `SELECT * FROM news_articles WHERE slug = $1 AND status = 'published';`;
    const result = await db.query(query, [slug]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'News article not found' });
    res.json(result.rows[0]);
  } catch (error) { console.error(`Error fetching news article ${slug}:`, error); res.status(500).json({ error: 'Internal Server Error fetching news article' }); }
});

// --- Authentication Routes (Public) ---

// POST /api/auth/register - User Registration
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Validation
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters long.' });

  try {
    // Check if email exists
    const userCheck = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) return res.status(409).json({ error: 'Email already registered.' });

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert user
    const insertQuery = `INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at;`;
    const newUserResult = await db.query(insertQuery, [name, email, passwordHash]);
    const newUser = newUserResult.rows[0];

    console.log(`User registered: ${newUser.email} (ID: ${newUser.id})`);
    res.status(201).json({ message: 'User registered successfully!', user: { id: newUser.id, name: newUser.name, email: newUser.email } });

  } catch (error) { console.error('Error during registration:', error); res.status(500).json({ error: 'Internal Server Error during registration.' }); }
});

// POST /api/auth/login - User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format.' });
  if (!JWT_SECRET) { console.error("FATAL: JWT_SECRET not set!"); return res.status(500).json({ error: "Server Configuration Error." }); }

  try {
    // Find user
    const userResult = await db.query('SELECT id, name, email, password_hash FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) { console.log(`Login fail: Email not found - ${email}`); return res.status(401).json({ error: 'Invalid email or password.' }); }

    const user = userResult.rows[0];

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) { console.log(`Login fail: Incorrect password - ${email}`); return res.status(401).json({ error: 'Invalid email or password.' }); }

    // Generate JWT
    const payload = { userId: user.id, email: user.email, name: user.name }; // Include name in payload
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }); // Expires in 1 day

    console.log(`User logged in: ${user.email} (ID: ${user.id})`);
    res.json({ message: 'Login successful!', token: token, user: { id: user.id, name: user.name, email: user.email } });

  } catch (error) { console.error('Error during login:', error); res.status(500).json({ error: 'Internal Server Error during login.' }); }
});


// --- User Favorite Routes (Protected by authenticateToken middleware) ---

// GET /api/users/me/favorites - Get IDs of favorited tools for the logged-in user
app.get('/api/users/me/favorites', authenticateToken, async (req, res) => {
  // req.user is populated by authenticateToken middleware
  const userId = req.user.userId;

  try {
    const query = `SELECT tool_id FROM user_favorites WHERE user_id = $1;`;
    const result = await db.query(query, [userId]);
    const favoriteToolIds = result.rows.map(row => row.tool_id);
    res.json({ favoriteToolIds });
  } catch (error) { console.error(`Error fetching favorites for user ${userId}:`, error); res.status(500).json({ error: 'Internal Server Error fetching favorites.' }); }
});

// POST /api/tools/:toolId/favorite - Add a tool to favorites
app.post('/api/tools/:toolId/favorite', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const toolId = parseInt(req.params.toolId, 10);

  if (isNaN(toolId)) return res.status(400).json({ error: 'Invalid tool ID.' });

  try {
    // Optional: Check if tool exists before favoriting
    const toolCheck = await db.query('SELECT id FROM tools WHERE id = $1', [toolId]);
    if (toolCheck.rows.length === 0) return res.status(404).json({ error: 'Tool not found.' });

    const insertQuery = `INSERT INTO user_favorites (user_id, tool_id) VALUES ($1, $2) ON CONFLICT (user_id, tool_id) DO NOTHING;`;
    await db.query(insertQuery, [userId, toolId]);

    console.log(`User ${userId} favorited tool ${toolId}`);
    res.status(201).json({ message: 'Tool added to favorites.' }); // Use 201 for resource creation intention
  } catch (error) { console.error(`Error adding favorite for user ${userId}, tool ${toolId}:`, error); res.status(500).json({ error: 'Internal Server Error adding favorite.' }); }
});

// DELETE /api/tools/:toolId/favorite - Remove a tool from favorites
app.delete('/api/tools/:toolId/favorite', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const toolId = parseInt(req.params.toolId, 10);

  if (isNaN(toolId)) return res.status(400).json({ error: 'Invalid tool ID.' });

  try {
    const deleteQuery = `DELETE FROM user_favorites WHERE user_id = $1 AND tool_id = $2;`;
    const result = await db.query(deleteQuery, [userId, toolId]);

    if (result.rowCount > 0) { console.log(`User ${userId} unfavorited tool ${toolId}`); }
    // No error if row didn't exist, the state is achieved
    res.status(200).json({ message: 'Tool removed from favorites.' }); // OK is fine here

  } catch (error) { console.error(`Error removing favorite for user ${userId}, tool ${toolId}:`, error); res.status(500).json({ error: 'Internal Server Error removing favorite.' }); }
});


// --- Start the server ---
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});

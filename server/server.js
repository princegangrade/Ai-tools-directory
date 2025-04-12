require('dotenv').config(); // LOAD ENV VARS FIRST!

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db'); // Your db module using pg
const authenticateToken = require('./middleware/auth'); // Import JWT middleware

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET is not defined in the environment variables. Please check your .env file.");
    process.exit(1); // Exit if the secret is missing
}

// --- Middleware ---
// !! IMPORTANT FOR PRODUCTION: Restrict CORS to your specific frontend domain
// Example: app.use(cors({ origin: 'https://your-frontend-domain.com' }));
app.use(cors()); // Enable CORS (adjust for production)
app.use(express.json()); // Parse JSON bodies

// --- Helper --- Basic Email Validation
function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// --- API Routes ---

// Root endpoint
app.get('/', (req, res) => {
    res.send('AI Tools Directory API is running!');
});

// --- Tool Routes (Public/Filtered) ---
app.get('/api/tools', async (req, res) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 9;
    const offset = (page - 1) * limit;
    const categorySlug = req.query.category;
    const searchTerm = req.query.search ? `%${String(req.query.search).replace(/[%_]/g, '\\$&')}%` : null;
    const sortBy = req.query.sort || 'popularity';
    const tags = req.query.tags ? req.query.tags.split(',').map(tag => String(tag).trim()).filter(tag => tag) : null; // Keep case for potential future needs, lowercase in query
    const pricing = req.query.pricing;

    let queryParams = [];
    let baseSelect = `
        SELECT
            t.id, t.name, t.slug, t.description, t.website_url, t.try_now_url, t.image_url,
            t.pricing_text, t.pricing_low, t.rating_avg, t.review_count,
            COALESCE(t.tags_array, '{}'::text[]) as tags_array,
            c.name AS category_name, c.slug AS category_slug,
            t.vendor_name
    `;
    let baseWhere = ` WHERE t.status = 'approved' `;
    let whereClauses = [];

    if (categorySlug && categorySlug !== 'all') {
        queryParams.push(categorySlug);
        whereClauses.push(`c.slug = $${queryParams.length}`);
    }

    if (searchTerm) {
        queryParams.push(searchTerm);
        const searchParamIndex = queryParams.length;
        whereClauses.push(`(
            t.name ILIKE $${searchParamIndex} OR
            t.description ILIKE $${searchParamIndex} OR
            t.vendor_name ILIKE $${searchParamIndex} OR
            EXISTS (SELECT 1 FROM unnest(COALESCE(t.tags_array, '{}')) AS tag WHERE tag ILIKE $${searchParamIndex})
        )`);
    }

    // CORRECTED TAG FILTERING (Checks for overlap, case-insensitive)
    if (tags && tags.length > 0) {
        queryParams.push(tags.map(t => t.toLowerCase())); // Convert filter tags to lowercase for comparison
        whereClauses.push(`ARRAY(SELECT lower(unnest(COALESCE(t.tags_array, '{}')))) && $${queryParams.length}`);
    }

    if (pricing) {
        switch (pricing) {
            case 'free': whereClauses.push(`t.pricing_low = 0`); break;
            case 'freemium': whereClauses.push(`(t.pricing_low = 0 OR lower(t.pricing_text) LIKE '%freemium%')`); break;
            case 'paid': whereClauses.push(`t.pricing_low > 0`); break;
        }
    }

    if (whereClauses.length > 0) {
        baseWhere += ` AND ${whereClauses.join(' AND ')}`;
    }

    let orderByClause = ' ORDER BY ';
    switch (sortBy) {
        case 'rating':
        case 'rating_desc':
            orderByClause += 't.rating_avg DESC NULLS LAST, t.review_count DESC NULLS LAST, t.id ASC'; break;
        case 'newest':
            orderByClause += 't.created_at DESC, t.id ASC'; break;
        case 'price_asc':
            orderByClause += 'CASE WHEN t.pricing_low = 0 THEN 0 ELSE 1 END ASC, t.pricing_low ASC NULLS LAST, t.id ASC'; break;
        case 'name_asc':
            orderByClause += 't.name ASC'; break;
        case 'popularity':
        default:
            orderByClause += 't.review_count DESC NULLS LAST, t.rating_avg DESC NULLS LAST, t.id ASC'; break;
    }

    const toolsQuery = `
        ${baseSelect}
        FROM tools t
        LEFT JOIN categories c ON t.category_id = c.id
        ${baseWhere}
        ${orderByClause}
        LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}
    `;
    const countQuery = `
        SELECT COUNT(*)
        FROM tools t
        LEFT JOIN categories c ON t.category_id = c.id
        ${baseWhere}
    `;

    try {
        const countResult = await db.query(countQuery, queryParams);
        const totalTools = parseInt(countResult.rows[0]?.count || '0', 10);
        const totalPages = Math.ceil(totalTools / limit);

        const finalQueryParams = [...queryParams, limit, offset];
        const result = await db.query(toolsQuery, finalQueryParams);

        res.json({
            tools: result.rows,
            pagination: {
                currentPage: page,
                totalPages: totalPages,
                totalTools: totalTools,
                limit: limit
            }
        });
    } catch (error) {
        console.error('Error fetching tools:', { route: req.originalUrl, query: req.query, error: error.stack });
        res.status(500).json({ error: 'Internal Server Error fetching tools.' });
    }
});


// GET /api/tools/slug-to-id/:slug
app.get('/api/tools/slug-to-id/:slug', async (req, res) => {
    const { slug } = req.params;
    if (!slug) return res.status(400).json({ error: 'Tool slug is required.' });

    try {
        const result = await db.query('SELECT id FROM tools WHERE slug = $1 AND status = \'approved\'', [slug]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Tool not found or not approved' });
        res.json({ id: result.rows[0].id });
    } catch (error) {
        console.error(`Error fetching ID for slug ${slug}:`, error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// GET /api/tools/:slug
app.get('/api/tools/:slug', async (req, res) => {
    const { slug } = req.params;
    if (!slug) return res.status(400).json({ error: 'Tool slug is required.' });

    try {
        const query = `
            SELECT
                t.id, t.name, t.slug, t.description, t.website_url, t.try_now_url, t.image_url,
                t.pricing_text, t.pricing_low, t.pricing_high, t.rating_avg, t.review_count,
                COALESCE(t.tags_array, '{}'::text[]) as tags_array,
                COALESCE(t.features_json, '{}'::jsonb) as features_json,
                COALESCE(t.screenshots_array, '{}'::text[]) as screenshots_array,
                COALESCE(t.pricing_tiers_json, '[]'::jsonb) as pricing_tiers_json,
                t.documentation_url,
                COALESCE(t.alternatives_array, '{}'::text[]) as alternatives_array,
                t.created_at, t.updated_at,
                c.name AS category_name, c.slug AS category_slug,
                t.vendor_name
            FROM tools t
            LEFT JOIN categories c ON t.category_id = c.id
            WHERE t.slug = $1 AND t.status = 'approved'
        `;
        const result = await db.query(query, [slug]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Tool not found or not approved' });
        res.json(result.rows[0]);
    } catch (error) {
        console.error(`Error fetching tool ${slug}:`, error);
        res.status(500).json({ error: 'Internal Server Error fetching tool details' });
    }
});

// GET /api/tools/compare
app.get('/api/tools/compare', async (req, res) => {
    const idsQuery = req.query.ids;
    if (!idsQuery) return res.status(400).json({ error: 'Tool IDs are required.' });

    const ids = idsQuery.split(',').map(id => parseInt(id, 10)).filter(id => !isNaN(id) && id > 0);
    if (ids.length < 2 || ids.length > 4) return res.status(400).json({ error: 'Invalid or incorrect number of tool IDs (min 2, max 4).' });

    try {
        const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
        const query = `
            SELECT
                t.id, t.name, t.slug, t.description, t.website_url, t.try_now_url, t.image_url,
                t.pricing_text, t.pricing_low, t.rating_avg, t.review_count,
                COALESCE(t.tags_array, '{}'::text[]) as tags_array,
                COALESCE(t.features_json, '{}'::jsonb) as features_json,
                COALESCE(t.screenshots_array, '{}'::text[]) as screenshots_array,
                COALESCE(t.pricing_tiers_json, '[]'::jsonb) as pricing_tiers_json,
                t.documentation_url,
                COALESCE(t.alternatives_array, '{}'::text[]) as alternatives_array,
                t.created_at, t.updated_at,
                c.name AS category_name, c.slug AS category_slug,
                t.vendor_name
            FROM tools t
            LEFT JOIN categories c ON t.category_id = c.id
            WHERE t.id IN (${placeholders}) AND t.status = 'approved'
        `;
        const result = await db.query(query, ids);
        // Ensure results are returned in the same order as requested IDs
        const sortedResults = ids.map(id => result.rows.find(row => row.id === id)).filter(Boolean);

        if (sortedResults.length < ids.length) {
             console.warn(`Compare requested IDs [${ids.join(',')}] but found only [${sortedResults.map(r=>r.id).join(',')}]`);
        }
        if (sortedResults.length < 2) { // Need at least 2 found tools
             return res.status(404).json({ error: `Could not find at least two of the requested tools (IDs: ${ids.join(', ')}).` });
        }

        res.json(sortedResults);
    } catch (error) {
        console.error('Error fetching comparison data:', error);
        res.status(500).json({ error: 'Internal Server Error fetching comparison data.' });
    }

// Inside GET /api/tools/compare in server.js
try {
  // ... (build query) ...
  const result = await db.query(query, ids);
  // **** ADD LOGGING HERE ****
  console.log(`Compare Route - DB Query Result for IDs [${ids.join(', ')}]:`, JSON.stringify(result.rows, null, 2));
  // **************************

  // Ensure results are returned in the order requested
  const sortedResults = ids.map(id => result.rows.find(row => row.id === id)).filter(Boolean);
  // **** ADD MORE LOGGING HERE ****
  console.log(`Compare Route - Sorted/Filtered Results Length: ${sortedResults.length}`);
  // *****************************

  // It's possible some requested IDs weren't found/approved
  if (sortedResults.length < ids.length) { // Check if we found fewer than requested
       console.warn(`Compare Route: Requested ${ids.length} tools, but only found ${sortedResults.length} approved tools.`);
  }
  // Send 404 only if ZERO tools were found
  if (sortedResults.length < 1) {
       console.error(`Compare Route: No approved tools found for requested IDs [${ids.join(', ')}]. Sending 404.`);
       return res.status(404).json({ error: 'No requested tools were found or approved.' });
  }

  res.json(sortedResults);
} catch (error) {
 // ...
}
});


// --- News Routes ---
app.get('/api/news', async (req, res) => {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 3;
    const offset = (page - 1) * limit;

    try {
        const query = `
            SELECT id, title, slug, image_url, content, published_date, author, category, created_at
            FROM news_articles
            WHERE status = 'published'
            ORDER BY published_date DESC, created_at DESC
            LIMIT $1 OFFSET $2
        `;
        const countQuery = `SELECT COUNT(*) FROM news_articles WHERE status = 'published'`;

        const [result, countResult] = await Promise.all([
            db.query(query, [limit, offset]),
            db.query(countQuery)
        ]);

        const totalNews = parseInt(countResult.rows[0]?.count || '0', 10);
        const totalPages = Math.ceil(totalNews / limit);

        res.json({
            news: result.rows,
            pagination: {
                currentPage: page,
                totalPages: totalPages,
                totalNews: totalNews,
                limit: limit
            }
        });
    } catch (error) {
        console.error('Error fetching news:', error);
        res.status(500).json({ error: 'Internal Server Error fetching news' });
    }
});

app.get('/api/news/:slug', async (req, res) => {
    const { slug } = req.params;
    if (!slug) return res.status(400).json({ error: 'News slug is required.' });

    try {
        const query = `
            SELECT id, title, slug, image_url, content, published_date, author, category, created_at, updated_at
            FROM news_articles
            WHERE slug = $1 AND status = 'published'
        `;
        const result = await db.query(query, [slug]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'News article not found or not published' });
        res.json(result.rows[0]);
    } catch (error) {
        console.error(`Error fetching news article ${slug}:`, error);
        res.status(500).json({ error: 'Internal Server Error fetching news article' });
    }
});

// --- Authentication Routes ---
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format.' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters long.' });

    try {
        const userCheck = await db.query('SELECT id FROM users WHERE lower(email) = lower($1)', [email]);
        if (userCheck.rows.length > 0) return res.status(409).json({ error: 'Email address is already registered.' });

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const insertQuery = `
            INSERT INTO users (name, email, password_hash)
            VALUES ($1, $2, $3)
            RETURNING id, name, email, created_at
        `;
        const newUserResult = await db.query(insertQuery, [name.trim(), email.trim().toLowerCase(), passwordHash]);
        const newUser = newUserResult.rows[0];

        // console.log(`User registered: ${newUser.email} (ID: ${newUser.id})`);
        res.status(201).json({
            message: 'User registered successfully! Please sign in.',
            user: { id: newUser.id, name: newUser.name, email: newUser.email }
        });
    } catch (error) {
        console.error('Error during registration:', error);
        if (error.code === '23505') return res.status(409).json({ error: 'Email address is already registered.' });
        res.status(500).json({ error: 'Internal Server Error during registration.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
    if (!isValidEmail(email)) return res.status(401).json({ error: 'Invalid email or password.' });

    try {
        const userResult = await db.query('SELECT id, name, email, password_hash FROM users WHERE lower(email) = lower($1)', [email]);
        if (userResult.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });

        const user = userResult.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) return res.status(401).json({ error: 'Invalid email or password.' });

        const payload = { userId: user.id, email: user.email, name: user.name };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });

        // console.log(`User logged in: ${user.email} (ID: ${user.id})`);
        res.json({
            message: 'Login successful!',
            token: token,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error during login.' });
    }
});

// --- Review Routes ---
app.get('/api/tools/:toolId/reviews', async (req, res) => {
    const toolId = parseInt(req.params.toolId, 10);
    if (isNaN(toolId) || toolId <= 0) return res.status(400).json({ error: 'Invalid tool ID.' });

    try {
        const query = `
            SELECT r.id, r.rating, r.review_text, r.created_at, r.updated_at, u.name AS user_name
            FROM reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.tool_id = $1
            ORDER BY r.created_at DESC
        `;
        const result = await db.query(query, [toolId]);
        res.json(result.rows);
    } catch (error) {
        console.error(`Error fetching reviews for tool ${toolId}:`, error);
        res.status(500).json({ error: 'Internal Server Error fetching reviews.' });
    }
});

app.post('/api/tools/:toolId/reviews', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const toolId = parseInt(req.params.toolId, 10);
    const { rating, reviewText } = req.body;

    if (isNaN(toolId) || toolId <= 0) return res.status(400).json({ error: 'Invalid tool ID.' });
    const ratingInt = parseInt(rating, 10);
    if (isNaN(ratingInt) || ratingInt < 1 || ratingInt > 5) return res.status(400).json({ error: 'Rating must be an integer between 1 and 5.' });

    try {
        const toolCheck = await db.query('SELECT id FROM tools WHERE id = $1 AND status = \'approved\'', [toolId]);
        if (toolCheck.rows.length === 0) return res.status(404).json({ error: 'Tool not found or not approved.' });

        const query = `
            INSERT INTO reviews (tool_id, user_id, rating, review_text)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tool_id, user_id) DO UPDATE
                SET rating = EXCLUDED.rating,
                    review_text = EXCLUDED.review_text,
                    updated_at = NOW()
            RETURNING *
        `;
        const result = await db.query(query, [toolId, userId, ratingInt, reviewText || null]);

        // console.log(`User ${userId} submitted/updated review for tool ${toolId}`);
        res.status(201).json({
            message: 'Review submitted successfully.',
            review: result.rows[0]
        });
    } catch (error) {
        console.error(`Error submitting review user ${userId}, tool ${toolId}:`, error);
        if (error.code === '23503') return res.status(400).json({ error: 'Invalid user or tool reference.' });
        res.status(500).json({ error: 'Internal Server Error submitting review.' });
    }
});

// --- User Favorite Routes ---
app.get('/api/users/me/favorites', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const query = `SELECT tool_id FROM user_favorites WHERE user_id = $1`;
        const result = await db.query(query, [userId]);
        const favoriteToolIds = result.rows.map(row => row.tool_id);
        res.json({ favoriteToolIds });
    } catch (error) {
        console.error(`Error fetching favorites for user ${userId}:`, error);
        res.status(500).json({ error: 'Internal Server Error fetching favorites.' });
    }
});

app.post('/api/tools/:toolId/favorite', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const toolId = parseInt(req.params.toolId, 10);

    if (isNaN(toolId) || toolId <= 0) return res.status(400).json({ error: 'Invalid tool ID.' });

    try {
        const toolCheck = await db.query('SELECT id FROM tools WHERE id = $1 AND status = \'approved\'', [toolId]);
        if (toolCheck.rows.length === 0) return res.status(404).json({ error: 'Tool not found or not approved.' });

        const insertQuery = `
            INSERT INTO user_favorites (user_id, tool_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, tool_id) DO NOTHING
        `;
        await db.query(insertQuery, [userId, toolId]);

        // console.log(`User ${userId} favorited tool ${toolId}`);
        res.status(201).json({ message: 'Tool added to favorites successfully.' });
    } catch (error) {
        console.error(`Error adding favorite for user ${userId}, tool ${toolId}:`, error);
        res.status(500).json({ error: 'Internal Server Error adding favorite.' });
    }
});

app.delete('/api/tools/:toolId/favorite', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const toolId = parseInt(req.params.toolId, 10);

    if (isNaN(toolId) || toolId <= 0) return res.status(400).json({ error: 'Invalid tool ID.' });

    try {
        const deleteQuery = `DELETE FROM user_favorites WHERE user_id = $1 AND tool_id = $2`;
        const result = await db.query(deleteQuery, [userId, toolId]);

        // console.log(`User ${userId} unfavorited tool ${toolId} (${result.rowCount > 0 ? 'success' : 'not found'})`);
        res.status(200).json({ message: 'Tool removed from favorites (if it was present).' });
    } catch (error) {
        console.error(`Error removing favorite for user ${userId}, tool ${toolId}:`, error);
        res.status(500).json({ error: 'Internal Server Error removing favorite.' });
    }
});

// --- Tool Submission Route ---
app.post('/api/tools/submit', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { name, website_url, category_slug, description, pricing_text, tags, vendor_name } = req.body;

    if (!name || !website_url || !category_slug || !description) return res.status(400).json({ error: 'Name, website URL, category, and description are required.' });
    try { new URL(website_url); } catch (_) { return res.status(400).json({ error: 'Invalid website URL format.' }); }

    try {
        const catRes = await db.query('SELECT id FROM categories WHERE slug = $1', [category_slug]);
        if (catRes.rows.length === 0) return res.status(400).json({ error: 'Invalid category selected.' });
        const categoryId = catRes.rows[0].id;

        let baseSlug = String(name).toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '').replace(/--+/g, '-').replace(/^-+/, '').replace(/-+$/, '') || `tool-${Date.now()}`;
        let finalSlug = baseSlug;
        let suffix = 1;
        while (true) {
            const slugCheck = await db.query('SELECT id FROM tools WHERE slug = $1', [finalSlug]);
            if (slugCheck.rows.length === 0) break;
            finalSlug = `${baseSlug}-${suffix++}`;
            if (suffix > 10) { // Prevent infinite loop in unlikely scenario
                console.error(`Could not generate unique slug for tool "${name}" after 10 attempts.`);
                return res.status(500).json({ error: 'Could not generate unique identifier for the tool.' });
            }
        }

        const tagsArray = tags ? String(tags).split(',').map(tag => tag.trim()).filter(Boolean) : null; // Store tags with original case, filter lowercase when querying

        const query = `
            INSERT INTO tools (
                name, slug, website_url, category_id, description, pricing_text, tags_array,
                submitted_by_user_id, status, vendor_name
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9)
            RETURNING id, name, slug
        `;
        const result = await db.query(query, [
            name.trim(), finalSlug, website_url.trim(), categoryId, description.trim(),
            pricing_text ? pricing_text.trim() : null, tagsArray, userId, vendor_name ? vendor_name.trim() : null
        ]);

        // console.log(`User ${userId} submitted tool: ${result.rows[0].name} (ID: ${result.rows[0].id})`);
        res.status(201).json({
            message: 'Tool submitted successfully and is pending review.',
            tool: result.rows[0]
        });
    } catch (error) {
        console.error(`Error submitting tool by user ${userId}:`, error);
        if (error.code === '23505') return res.status(409).json({ error: 'A tool with this name or website might already exist or be under review.' });
        res.status(500).json({ error: 'Internal Server Error submitting tool.' });
    }
});


// --- AI Matchmaker Route ---
app.post('/api/matchmaker', async (req, res) => {
    const { useCase, budget, skillLevel, industry, task } = req.body;

    try {
        let queryParams = [];
        let baseSelect = `
            SELECT
                t.id, t.name, t.slug, t.description, t.rating_avg, t.review_count,
                t.image_url, t.pricing_text, t.website_url, t.try_now_url,
                c.name as category_name, c.slug as category_slug,
                t.vendor_name
        `;
        let fromJoin = `
            FROM tools t
            LEFT JOIN categories c ON t.category_id = c.id
        `;
        let baseWhere = ` WHERE t.status = 'approved' `;
        let whereClauses = [];
        let scoreClauses = [];

        // --- Scoring Weights (Adjustable) ---
        const W_CATEGORY = 20;
        const W_TASK_NAME = 8;
        const W_TASK_DESC = 5;
        const W_TASK_TAG = 3;
        const W_SKILL = 5;
        const W_INDUSTRY = 4;
        const W_RATING = 1.5;
        const W_REVIEW_COUNT = 1; // Using LN(reviews+1)

        // Map frontend use case names to backend category slugs
        const categoryMap = {
            'Text Generation': 'text-ai', 'Image Creation': 'image-ai', 'Coding Assistance': 'code-ai',
            'Video Generation': 'video-ai', 'Audio Creation': 'audio-ai', 'Writing Improvement': 'utility-ai'
        };
        const targetCategorySlug = categoryMap[useCase];
        if (targetCategorySlug) {
            queryParams.push(targetCategorySlug);
            scoreClauses.push(`(CASE WHEN c.slug = $${queryParams.length} THEN ${W_CATEGORY} ELSE 0 END)`);
        }

        // Budget Filtering (remains as a hard filter)
        if (budget) {
            if (budget === 'Free') whereClauses.push(`t.pricing_low = 0`);
            else if (budget === 'Low') whereClauses.push(`(t.pricing_low >= 0 AND t.pricing_low <= 20)`); // Corrected to include 0
            else if (budget === 'Mid') whereClauses.push(`(t.pricing_low > 20 AND t.pricing_low <= 50)`); // Corrected range
            else if (budget === 'High') whereClauses.push(`(t.pricing_low > 50)`);
            // Add scoring bonus for tools that exactly match 'Free' if requested
            if (budget === 'Free') {
                 scoreClauses.push(`(CASE WHEN t.pricing_low = 0 THEN 2 ELSE 0 END)`);
            }
        }

        // Task Scoring (using ILIKE for case-insensitivity)
        if (task && String(task).trim()) {
            const taskPattern = `%${String(task).trim().replace(/[%_]/g, '\\$&')}%`;
            queryParams.push(taskPattern);
            const taskParamIndex = queryParams.length;
            scoreClauses.push(`
                (CASE WHEN t.name ILIKE $${taskParamIndex} THEN ${W_TASK_NAME} ELSE 0 END) +
                (CASE WHEN t.description ILIKE $${taskParamIndex} THEN ${W_TASK_DESC} ELSE 0 END) +
                (CASE WHEN EXISTS (SELECT 1 FROM unnest(COALESCE(t.tags_array, '{}')) tag WHERE tag ILIKE $${taskParamIndex}) THEN ${W_TASK_TAG} ELSE 0 END)
            `);
        }

        // Skill Level Scoring (case-insensitive tag check)
        if (skillLevel) {
            if (skillLevel === 'Beginner') {
                queryParams.push('easy'); queryParams.push('beginner');
                scoreClauses.push(`(CASE WHEN lower($${queryParams.length-1}) = ANY(ARRAY(SELECT lower(unnest(COALESCE(t.tags_array, '{}'))))) OR lower($${queryParams.length}) = ANY(ARRAY(SELECT lower(unnest(COALESCE(t.tags_array, '{}'))))) THEN ${W_SKILL} ELSE 0 END)`);
            } else if (skillLevel === 'Advanced') {
                queryParams.push('api'); queryParams.push('developer'); queryParams.push('expert');
                scoreClauses.push(`(CASE WHEN lower($${queryParams.length-2}) = ANY(ARRAY(SELECT lower(unnest(COALESCE(t.tags_array, '{}'))))) OR lower($${queryParams.length-1}) = ANY(ARRAY(SELECT lower(unnest(COALESCE(t.tags_array, '{}'))))) OR lower($${queryParams.length}) = ANY(ARRAY(SELECT lower(unnest(COALESCE(t.tags_array, '{}'))))) THEN ${W_SKILL} ELSE 0 END)`);
            }
            // Intermediate gets no specific bonus/penalty based on tags here, relies on other factors
        }

        // Industry Scoring (case-insensitive tag check)
        if (industry && String(industry).trim()) {
            queryParams.push(String(industry).trim().toLowerCase());
            scoreClauses.push(`(CASE WHEN lower($${queryParams.length}) = ANY(ARRAY(SELECT lower(unnest(COALESCE(t.tags_array, '{}'))))) THEN ${W_INDUSTRY} ELSE 0 END)`);
        }

        // Base Score Components
        scoreClauses.push(`(COALESCE(t.rating_avg, 0) * ${W_RATING})`); // Rating bonus
        scoreClauses.push(`(LN(COALESCE(t.review_count, 0) + 1) * ${W_REVIEW_COUNT})`); // Review count bonus (log scaled)

        // Construct Final Query
        if (whereClauses.length > 0) baseWhere += ` AND ${whereClauses.join(' AND ')}`;
        const orderByClause = ` ORDER BY (${scoreClauses.join(' + ')}) DESC NULLS LAST LIMIT 5`; // Get top 5 matches

        const finalQuery = baseSelect + fromJoin + baseWhere + orderByClause;
        const result = await db.query(finalQuery, queryParams);
        res.json({ recommendations: result.rows });
    } catch (error) {
        console.error('Matchmaker Error:', error);
        res.status(500).json({ error: 'Internal Server Error during matchmaking.' });
    }
});


// --- Error Handling Middleware ---
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err.stack || err);
    res.status(500).json({ error: 'Something went wrong on the server!' });
});

// --- 404 Handler ---
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
    // Removed JWT_SECRET log here as it's checked at the top
});

// server/db.js
// NOTE: Ensure require('dotenv').config(); is the VERY FIRST line in server/server.js

const { Pool } = require('pg'); // Use the pg Pool

// Create the Pool using environment variables
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  // Optional: Add connection timeout or other pool options if needed
  // connectionTimeoutMillis: 5000, // Example: 5 seconds
  // idleTimeoutMillis: 10000,      // Example: 10 seconds
  // max: 10,                       // Example: Max 10 clients in pool
});

// Optional: Test the connection on startup
pool.connect((err, client, release) => {
  if (err) {
    // Log a more informative error if connection fails
    return console.error(`Error connecting to PostgreSQL database "${process.env.DB_DATABASE}" as user "${process.env.DB_USER}" on host "${process.env.DB_HOST}:${process.env.DB_PORT}":`, err.stack);
  }
  if(client) {
     // If connection is successful, log the actual database name connected to
     console.log(`Database "${client.database}" connected successfully!`);
     client.release(); // Release the client back to the pool
  } else {
     console.warn('Pool connect callback received null client.');
  }
});

// Add error listener for idle clients (good practice)
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle PostgreSQL client', err);
  // Decide if you need to take action, e.g., process.exit(1);
});

module.exports = {
  // Function to execute queries using the pool
  query: (text, params) => pool.query(text, params),
  // Export the pool itself if direct access is needed (e.g., for transactions)
  pool,
};

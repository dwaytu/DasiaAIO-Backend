// Simple Node.js seeder using pg library
const { Client } = require('pg');
const fs = require('fs');

const connectionString = (process.env.DATABASE_URL || '').trim();

if (!connectionString) {
  console.error('DATABASE_URL is required to run the seeder.');
  process.exit(1);
}

const sslMode = (process.env.DATABASE_SSL_MODE || '').trim().toLowerCase();
const clientConfig = { connectionString };

if (sslMode === 'require') {
  clientConfig.ssl = { rejectUnauthorized: true };
} else if (sslMode === 'no-verify') {
  clientConfig.ssl = { rejectUnauthorized: false };
}

const client = new Client(clientConfig);

async function seed() {
  try {
    await client.connect();
    console.log('Connected to database');

    const sql = fs.readFileSync('seed_dashboard.sql', 'utf8');
    await client.query(sql);

    console.log('Database seeded successfully!');
  } catch (err) {
    console.error('Error seeding database:', err);
    process.exit(1);
  } finally {
    await client.end();
  }
}

seed();

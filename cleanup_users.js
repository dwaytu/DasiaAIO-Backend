// Cleanup corrupted test users
const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

// Parse .env file manually
function parseEnv(filePath) {
  const env = {};
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const [key, ...valueParts] = trimmed.split('=');
        env[key.trim()] = valueParts.join('=').trim();
      }
    });
  } catch (err) {
    console.error('Error reading .env:', err.message);
  }
  return env;
}

const envVars = parseEnv(path.join(__dirname, '.env'));
const connectionString = envVars.DATABASE_URL || 'postgresql://postgres:kXgebinlNjUyAMwhaQFUpihblOZYqrIw@dpg-cu2d64hu0jms73836gog-a.oregon-postgres.render.com/railway';

console.log(`📡 Connecting to database...\n`);

let client;

async function findWorkingConnection() {
  try {
    client = new Client({
      connectionString,
      ssl: { rejectUnauthorized: false },
    });
    
    console.log('Attempting connection...');
    await client.connect();
    console.log('✓ Connected to Railway database\n');
    return true;
  } catch (err) {
    console.error('❌ Connection error:', err.message);
    console.error('Error code:', err.code);
    console.error('Error details:', err);
    return false;
  }
}

async function cleanup() {
  try {
    const connected = await findWorkingConnection();
    if (!connected) {
      console.error('❌ Could not connect to any database');
      process.exit(1);
    }

    // First, show what we're deleting
    console.log('\n📋 Corrupted users to be deleted:\n');
    const checkResult = await client.query(`
      SELECT id, username, email, full_name 
      FROM users 
      WHERE role != 'admin' 
        AND (
          email LIKE '%@gmail.com%'
          OR email LIKE '%@test.local%'
          OR full_name LIKE '%Updated%'
          OR full_name LIKE '%Test%'
        )
      ORDER BY created_at DESC
    `);

    console.log(checkResult.rows);
    console.log(`\nTotal to delete: ${checkResult.rows.length}`);

    if (checkResult.rows.length === 0) {
      console.log('\n✓ No corrupted users found! Database is clean.');
      await client.end();
      return;
    }

    // Delete corrupted users
    const deleteResult = await client.query(`
      DELETE FROM users 
      WHERE role != 'admin' 
        AND (
          email LIKE '%@gmail.com%'
          OR email LIKE '%@test.local%'
          OR full_name LIKE '%Updated%'
          OR full_name LIKE '%Test%'
        )
    `);

    console.log(`\n✓ Deleted ${deleteResult.rowCount} corrupted users`);

    // Show remaining guards
    console.log('\n✅ Remaining guards in database:\n');
    const remainingResult = await client.query(
      `SELECT id, username, email, full_name 
       FROM users 
       WHERE role != 'admin'
       ORDER BY full_name`
    );

    console.log(remainingResult.rows);
    console.log(`\nTotal guards: ${remainingResult.rows.length}`);

    await client.end();
    console.log('\n✓ Cleanup complete!');
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  }
}

cleanup();

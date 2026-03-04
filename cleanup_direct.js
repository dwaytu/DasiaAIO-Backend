// Direct cleanup with retry logic
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Read .env
function parseEnv(filePath) {
  const env = {};
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
          const key = trimmed.substring(0, eqIdx).trim();
          const value = trimmed.substring(eqIdx + 1).trim();
          env[key] = value;
        }
      }
    });
  } catch (err) {
    console.error('Error reading .env:', err.message);
  }
  return env;
}

const envVars = parseEnv(path.join(__dirname, '.env'));
const DATABASE_URL = envVars.DATABASE_URL;

console.log('🔧 Database Cleanup Tool\n');
console.log('Connecting to Railway PostgreSQL...');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
    minVersion: 'TLSv1.2'
  },
  statement_timeout: 30000,
  query_timeout: 30000,
  max: 1,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 30000,
  keepalives: 1,
  keepalives_idle: 30,
});

pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client:', err);
  process.exit(-1);
});

async function cleanup() {
  let client;
  try {
    client = await pool.connect();
    console.log('✓ Connected!\n');

    // Show what will be deleted
    console.log('📋 Finding corrupted users...\n');
    const selectResult = await client.query(`
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

    const corruptedUsers = selectResult.rows;
    console.log(`Found ${corruptedUsers.length} corrupted user(s):`);
    corruptedUsers.forEach(user => {
      console.log(`  - ${user.full_name || user.username} (${user.email})`);
    });

    if (corruptedUsers.length === 0) {
      console.log('\n✅ No corrupted users found! Database is already clean.\n');
      client.release();
      await pool.end();
      return;
    }

    // Delete them
    console.log('\n🗑️  Deleting corrupted users...');
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

    console.log(`✓ Deleted ${deleteResult.rowCount} user(s)\n`);

    // Show remaining guards
    console.log('👥 Remaining guards:\n');
    const remainingResult = await client.query(`
      SELECT id, username, email, full_name 
      FROM users 
      WHERE role != 'admin'
      ORDER BY full_name
    `);

    remainingResult.rows.forEach(user => {
      console.log(`  ✓ ${user.full_name || user.username} (${user.email})`);
    });

    console.log(`\n✅ Total guards: ${remainingResult.rows.length}`);
    console.log('\n✨ Cleanup complete! Your dropdowns should now show clean data.\n');

    client.release();
  } catch (err) {
    console.error('\n❌ Error:', err.message);
    console.error('Details:', err);
    if (client) client.release();
    process.exit(1);
  } finally {
    await pool.end();
  }
}

cleanup();

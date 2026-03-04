const pg = require('pg');

// Try different connection strings for local database
const connectionStrings = [
  'postgresql://postgres:postgres@localhost:5432/guard_firearm_system',
  'postgresql://postgres:password@localhost:5432/guard_firearm_system',
  'postgresql://postgres@localhost:5432/guard_firearm_system',
];

async function cleanup() {
  let client;
  
  // Try to connect
  for (const connString of connectionStrings) {
    try {
      client = new pg.Client({ connectionString: connString });
      await client.connect();
      console.log('✓ Connected to local database!\n');
      break;
    } catch (err) {
      client = null;
      continue;
    }
  }
  
  if (!client) {
    console.error('❌ Could not connect to local database');
    console.error('\nMake sure PostgreSQL Docker container is running:');
    console.error('  cd "d:\\Capstone Main\\DasiaAIO-Backend"');
    console.error('  docker-compose up -d postgres\n');
    process.exit(1);
  }

  try {
    console.log('🗑️  Deleting corrupted test data...\n');
    
    console.log('🗑️  Deleting corrupted test data...\n');
    
    // Delete corrupted users
    const delUsers = await client.query(
      `DELETE FROM users WHERE full_name LIKE $1 OR full_name LIKE $2 OR email LIKE $3`,
      ['%Updated%', '%Test%', '%@test.local%']
    );
    console.log(`✓ Deleted ${delUsers.rowCount} corrupted guard(s)`);
    
    // Delete corrupted firearms  
    const delFirearms = await client.query(
      `DELETE FROM firearms WHERE serial_number LIKE $1`,
      ['%TEST%']
    );
    console.log(`✓ Deleted ${delFirearms.rowCount} corrupted firearm(s)`);
    
    // Delete test vehicles
    const delVehicles = await client.query(
      `DELETE FROM armored_cars WHERE license_plate LIKE $1`,
      ['TEST-%']
    );
    console.log(`✓ Deleted ${delVehicles.rowCount} test vehicle(s)\n`);
    
    console.log('👥 Remaining clean data:\n');
    console.log('Guards:');
    const guards = await client.query(
      `SELECT id, username, email, full_name FROM users WHERE role != $1 ORDER BY full_name`,
      ['admin']
    );
    guards.rows.forEach(row => console.log(`  ✓ ${row.full_name || row.username} (${row.email})`));
    
    console.log('\nFirearms:');
    const firearms = await client.query(
      `SELECT id, serial_number, model FROM firearms WHERE status = $1 ORDER BY model`,
      ['available']
    );
    firearms.rows.forEach(row => console.log(`  ✓ ${row.serial_number} - ${row.model}`));
    
    console.log('\nVehicles:');
    const vehicles = await client.query(
      `SELECT id, license_plate, model FROM armored_cars WHERE status = $1 ORDER BY license_plate`,
      ['available']
    );
    vehicles.rows.forEach(row => console.log(`  ✓ ${row.license_plate} - ${row.model}`));
    
    console.log('\n✨ Cleanup complete! Refresh your browser to see clean dropdowns.\n');
    
  } catch (err) {
    console.error('\n❌ Error during cleanup:', err.message);
    process.exit(1);
  } finally {
    await client.end();
  }
}

cleanup();

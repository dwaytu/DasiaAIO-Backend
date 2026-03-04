-- DasiaAIO Database Cleanup Script
-- Remove corrupted test users to clean up dropdowns
-- Run this in Railway PostgreSQL dashboard or any SQL client

-- Step 1: View corrupted users to be deleted
SELECT 
    id, 
    username, 
    email, 
    full_name,
    created_at
FROM users 
WHERE role != 'admin' 
  AND (
    email LIKE '%@gmail.com%'
    OR email LIKE '%@test.local%'
    OR full_name LIKE '%Updated%'
    OR full_name LIKE '%Test%'
  )
ORDER BY created_at DESC;

-- Step 2: Delete corrupted users
DELETE FROM users 
WHERE role != 'admin' 
  AND (
    email LIKE '%@gmail.com%'
    OR email LIKE '%@test.local%'
    OR full_name LIKE '%Updated%'
    OR full_name LIKE '%Test%'
  );

-- Step 3: Verify cleanup - should show only the 8 clean seed guards
SELECT 
    id, 
    username, 
    email, 
    full_name,
    role
FROM users 
WHERE role != 'admin'
ORDER BY full_name;

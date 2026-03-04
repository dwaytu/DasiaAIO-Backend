-- Query to identify corrupted/test users
SELECT id, username, email, full_name, role 
FROM users 
WHERE role != 'admin' 
  AND (
    email LIKE '%@gmail.com%'
    OR email LIKE '%@test.local%'
    OR full_name LIKE '%Updated%'
    OR full_name LIKE '%Test%'
  )
ORDER BY created_at DESC;

-- Once confirmed, delete with:
-- DELETE FROM users 
-- WHERE role != 'admin' 
--   AND (
--     email LIKE '%@gmail.com%'
--     OR email LIKE '%@test.local%'
--     OR full_name LIKE '%Updated%'
--     OR full_name LIKE '%Test%'
--   );

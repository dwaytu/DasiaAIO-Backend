-- Seed guard users for testing
-- All passwords are: password123

INSERT INTO users (id, username, email, password, role, full_name, phone_number, license_number, license_expiry_date, verified)
VALUES
  ('guard-001', 'john_doe', 'john.doe@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'John Doe', '+1234567001', 'LIC-2024-001', '2027-01-15T00:00:00Z', true),
  ('guard-002', 'jane_smith', 'jane.smith@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'Jane Smith', '+1234567002', 'LIC-2024-002', '2027-02-20T00:00:00Z', true),
  ('guard-003', 'mike_johnson', 'mike.johnson@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'Mike Johnson', '+1234567003', 'LIC-2024-003', '2027-03-10T00:00:00Z', true),
  ('guard-004', 'sarah_williams', 'sarah.williams@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'Sarah Williams', '+1234567004', 'LIC-2024-004', '2027-01-25T00:00:00Z', true),
  ('guard-005', 'david_brown', 'david.brown@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'David Brown', '+1234567005', 'LIC-2024-005', '2027-04-05T00:00:00Z', true),
  ('guard-006', 'emily_davis', 'emily.davis@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'Emily Davis', '+1234567006', 'LIC-2024-006', '2027-02-14T00:00:00Z', true),
  ('guard-007', 'chris_miller', 'chris.miller@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'Chris Miller', '+1234567007', 'LIC-2024-007', '2027-03-22T00:00:00Z', true),
  ('guard-008', 'lisa_wilson', 'lisa.wilson@sentinel.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzEW5qBfAu', 'guard', 'Lisa Wilson', '+1234567008', 'LIC-2024-008', '2027-01-30T00:00:00Z', true)
ON CONFLICT (id) DO NOTHING;

-- Also add some firearms for testing if they don't exist
INSERT INTO firearms (id, name, serial_number, model, caliber, status)
VALUES
  ('firearm-003', 'Glock 17', 'SN-GLK-17001', 'Glock 17', '9mm', 'available'),
  ('firearm-004', 'Sig Sauer P320', 'SN-SIG-P320-001', 'Sig Sauer P320', '9mm', 'available'),
  ('firearm-005', 'Beretta 92FS', 'SN-BER-92-001', 'Beretta 92FS', '9mm', 'available'),
  ('firearm-006', 'Smith & Wesson M&P', 'SN-SW-MP-001', 'Smith & Wesson M&P', '9mm', 'available'),
  ('firearm-007', 'CZ P-09', 'SN-CZ-P09-001', 'CZ P-09', '9mm', 'available')
ON CONFLICT (serial_number) DO NOTHING;

-- Add some armored cars for testing
INSERT INTO armored_cars (id, license_plate, vin, model, manufacturer, capacity_kg, status)
VALUES
  ('car-001', 'ARM-001', 'VIN-ARM-SUV-001', 'Armored Suburban', 'Chevrolet', 500, 'available'),
  ('car-002', 'ARM-002', 'VIN-ARM-VAN-001', 'Armored Transit', 'Ford', 1000, 'available'),
  ('car-003', 'ARM-003', 'VIN-ARM-TRK-001', 'Armored F-550', 'Ford', 2000, 'available')
ON CONFLICT (id) DO NOTHING;


-- Store the road plate separately from the internal armored-car number.
ALTER TABLE armored_cars
    ADD COLUMN IF NOT EXISTS plate_number VARCHAR(50);

CREATE UNIQUE INDEX IF NOT EXISTS idx_armored_cars_plate_number_unique
    ON armored_cars (LOWER(BTRIM(plate_number)))
    WHERE plate_number IS NOT NULL AND BTRIM(plate_number) <> '';

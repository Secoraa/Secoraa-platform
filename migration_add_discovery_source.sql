-- Migration script to add discovery_source column to domains table
-- Run this with: psql -h <host> -p <port> -U <username> -d <database> -f migration_add_discovery_source.sql

-- Check if column exists and add it if it doesn't
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'domains' 
        AND column_name = 'discovery_source'
    ) THEN
        ALTER TABLE domains 
        ADD COLUMN discovery_source VARCHAR DEFAULT 'manual';
        
        -- Update existing rows
        UPDATE domains 
        SET discovery_source = 'manual' 
        WHERE discovery_source IS NULL;
        
        RAISE NOTICE 'Successfully added discovery_source column to domains table';
    ELSE
        RAISE NOTICE 'Column discovery_source already exists in domains table';
    END IF;
END $$;

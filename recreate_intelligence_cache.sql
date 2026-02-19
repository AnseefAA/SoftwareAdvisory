-- Drop the existing table
DROP TABLE IF EXISTS concert_advisory.intelligence_cache CASCADE;

-- Recreate with TEXT columns for JSON data (avoids UTF8/SQL_ASCII conversion issues)
CREATE TABLE concert_advisory.intelligence_cache
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    identifier text NOT NULL,
    identifier_type text NOT NULL,
    
    -- Use TEXT instead of JSONB to avoid encoding conversion issues
    raw_data text,  -- Will store JSON as text
    structured_data text,  -- Will store JSON as text
    
    -- Metadata
    sources_fetched text[],
    first_fetched_at timestamp with time zone DEFAULT now(),
    last_updated_at timestamp with time zone DEFAULT now(),
    fetch_count integer DEFAULT 1,
    
    -- Status tracking
    is_complete boolean DEFAULT false,
    fetch_errors text,  -- Will store JSON as text
    
    CONSTRAINT intelligence_cache_pkey PRIMARY KEY (id),
    CONSTRAINT intelligence_cache_identifier_key UNIQUE (identifier, identifier_type)
);

-- Create indexes for performance
CREATE INDEX idx_intelligence_cache_identifier ON concert_advisory.intelligence_cache(identifier);
CREATE INDEX idx_intelligence_cache_updated ON concert_advisory.intelligence_cache(last_updated_at);
CREATE INDEX idx_intelligence_cache_type ON concert_advisory.intelligence_cache(identifier_type);

-- Set ownership
ALTER TABLE concert_advisory.intelligence_cache OWNER to "12b12b08b15b95822f82407b";

-- Add comment
COMMENT ON TABLE concert_advisory.intelligence_cache IS 'Cache for aggregated CVE/Advisory intelligence data. Uses TEXT columns for JSON to avoid SQL_ASCII encoding issues.';

-- Made with Bob

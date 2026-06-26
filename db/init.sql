CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    target_name TEXT NOT NULL,
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    data_type TEXT,
    content TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    keyword_matched TEXT,
    severity TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
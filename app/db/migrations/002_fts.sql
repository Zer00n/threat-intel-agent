-- Full-text search virtual table for analyses
CREATE VIRTUAL TABLE IF NOT EXISTS analyses_fts USING fts5(
    id UNINDEXED,
    query,
    report_md,
    content=''
);

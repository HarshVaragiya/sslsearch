# Disk

# Elasticsearch

# Cassandra / ScyllaDB
```cqlsh
CREATE TABLE IF NOT EXISTS sslsearch  (
    record_ts TEXT,
    ip TEXT,
    port TEXT,
    subject TEXT,
    issuer TEXT,
    sans LIST<TEXT>,
    jarm TEXT,
    csp TEXT,
    region TEXT,
    meta TEXT,
    timestamp TIMESTAMP,
    headers MAP<TEXT, TEXT>,
    server TEXT,
    host TEXT,
    PRIMARY KEY ((ip, port, record_ts), timestamp)
) 
WITH compression = {
    'sstable_compression' : 'ZstdCompressor',
    'chunk_length_in_kb' : '128',
    'compression_level' : '22'
};
```

# Redis
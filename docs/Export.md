# Disk

- good for testing & one-off tasks.
- export is cert-result JSON (one record per line).
- output has low entropy and can be compressed to not waste disk space.

```bash
sslsearch <other flags> \
  --export.disk                                           # tells sslsearch to export findings to disk 
  --export.disk.filename 'result.log'                     # output file name 
```


# Elasticsearch

- good for historical data, archiving, security monitoring, dashboarding.
- index rate can be ~500-1000 docs/second with 6vCPUs & 12 GB RAM (k8s).
- export index would be `sslsearch-YYYY-MM-DD`.

```bash
sslsearch <other flags> \
  --export.elastic                                      # tells sslsearch to export findings to elasticsearch 
  --export.elastic.host 'https://192.168.0.192:9200'    # elasticsearch host 
  --export.elastic.username 'elastic'                   # elasticsearch username
  --export.elastic.password 'test-password'             # elasticsearch password
```


# Cassandra / ScyllaDB

- good for long term storage, archival, historical data.
- enabling `zstd` compression would save a lot of disk space compared to other solutions.
- querying data, etc would be more complicated than elasticsearch.

### Setup for Cassandra / ScyllaDB

- Create `recon` keyspace (you can skip if you have any other existing keyspace).

```cqlsh
create keyspace recon with replication = {'class': 'SimpleStrategy', 'replication_factor': 1};
```

- create the `sslsearch` table in the selected keyspace.

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

```bash
sslsearch <other flags> \
  --export.cassandra                                                  # tells sslsearch to export findings to cassandra
  --export.cassandra.connection-string 'https://192.168.0.192:9200'   # cassandra connection string (host)
  --export.cassandra.table 'recon.sslsearch'                          # cassandra table name: default "recon.sslsearch"
  --export.cassandra.result-ts-key '2024-11-25'                       # cassandra result ts key (for lifecycle managment)
```


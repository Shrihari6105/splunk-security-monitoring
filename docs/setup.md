# Setup

1. Install Splunk Enterprise and log in at `http://localhost:8000`.
2. Create indexes: `wineventlog`, `linux`, `network`, `web`.
3. Install the Universal Forwarder on each monitored host and point it at the indexer (port 9997).
4. Copy the relevant `configs/inputs/*.conf` into `$SPLUNK_HOME/etc/system/local/` on the forwarder.
5. Verify ingestion: `index=* | stats count by index, sourcetype`.

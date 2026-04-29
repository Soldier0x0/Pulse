db = db.getSiblingDB("cti");

db.createCollection("alerts");
db.alerts.createIndex({ cve_id: 1, severity_label: 1, created_at: -1 });
db.alerts.createIndex({ product: 1, created_at: -1 });
db.alerts.createIndex({ created_at: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 30 });

db.createCollection("correlation_state");
db.correlation_state.createIndex({ product: 1, last_alerted_at: -1 });

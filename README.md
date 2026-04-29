# CTI Platform

This project is a self-hosted cyber threat intelligence notification platform designed to aggregate open threat feeds, correlate overlapping signals, and notify analysts in near real-time. It is optimized for low-resource home-lab and small-team deployments where data sovereignty and operational simplicity matter.

The platform continuously ingests data from vulnerability feeds, exploit activity sources, and security news, then applies filtering, correlation, scoring, tagging, deduplication, and alert delivery. It is intentionally UI-ready via stable internal schemas while remaining headless-first for fast deployment and reliability.

## Architecture (ASCII)

```text
+------------------+      +------------------+      +------------------+
|  External Feeds  | ---> | Async Collectors | ---> |  Filter/Scoring  |
+------------------+      +------------------+      +------------------+
                                                      |
                                                      v
                                              +------------------+
                                              | Correlator/Dedup |
                                              +------------------+
                                               |       |       |
                                               v       v       v
                                          Telegram  Discord  MongoDB
                                                       |
                                                       v
                                                     Grafana
```

## Quick Start

1. Copy `.env.example` to `.env` and fill secrets.
2. Adjust watchlists and source toggles in `config.yml`.
3. Run `docker compose up -d` from `cti-platform`.

## Notes

- Weekly digest runs Monday 9:00 AM `Asia/Kolkata` by default.
- FastAPI portal is intentionally deferred but can be added later without pipeline rewrites.

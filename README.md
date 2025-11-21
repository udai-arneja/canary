# Canary

A security testing platform with automated website generation, vulnerability assessment, and attack monitoring.

## Services

- **Dashboard**: React app for monitoring security attacks and metrics
- **Multi-Website-Builder**: Automated tool that generates websites using an LLM with configurable vulnerability types
- **Deterministic-Websites**: Handmade websites with known vulnerabilities for security testing

## Getting Started

Run all services:

```bash
docker-compose up
```

Run specific services:

```bash
docker-compose up dashboard
docker-compose up multi-website-builder
docker-compose up deterministic-websites
```

## Ports

- Dashboard: `3000`
- Deterministic Websites: `8000`

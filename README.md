# Shodan MCP Server

[![npm version](https://badge.fury.io/js/shodan-mcp.svg)](https://www.npmjs.com/package/shodan-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server for the Shodan API v1. Provides comprehensive access to Shodan's network intelligence, vulnerability data, and security services through the MCP framework.

## Features

This server implements 15 tools covering all major Shodan v1 API functionality:

### Host Tools
- **host_lookup** - Look up a single IP address
- **host_batch_lookup** - Batch lookup up to 100 IPs

### Search Tools
- **shodan_search** - Search Shodan's database with query syntax
- **search_stats** - Get statistics and facets for a query

### Organization Tools
- **organization_lookup** - Lookup by organization name
- **network_lookup** - Lookup by CIDR block
- **domain_lookup** - Domain intelligence data
- **isp_lookup** - ASN/ISP lookup

### DNS Tools
- **dns_resolve** - Forward DNS lookup (hostname to IP)
- **dns_reverse** - Reverse DNS lookup (IP to hostname)

### Vulnerability Tools
- **cve_lookup** - Get CVE details
- **cpe_lookup** - Get CPE product information
- **cves_by_cpe** - Find CVEs for a CPE product
- **product_search** - Search for products

### Geospatial Tools
- **map_search** - Search hosts in a geographic area

## Installation

### Prerequisites
- Node.js 18+
- A Shodan API key (get one at https://account.shodan.io)

### Global Installation

```bash
npm install -g shodan-mcp
```

### Local Installation

```bash
npm install shodan-mcp
```

## Configuration

### Environment Variable

Set your Shodan API key:

```bash
export SHODAN_API_KEY="your-api-key-here"
```

### MCP Client Configuration

Add this to your MCP client settings (e.g., Cursor, Zed, Claude Desktop):

#### Using npx (recommended for testing)
```json
{
  "mcpServers": {
    "shodan": {
      "command": "npx",
      "args": ["-y", "shodan-mcp"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### Using globally installed binary
```json
{
  "mcpServers": {
    "shodan": {
      "command": "shodan-mcp",
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### Using Docker
```json
{
  "mcpServers": {
    "shodan": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/pingwin/shodan-mcp:latest"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Usage Examples

### Host Lookup
```typescript
host_lookup({ ip: "8.8.8.8" })
```

### Batch Host Lookup
```typescript
host_batch_lookup({ ips: ["8.8.8.8", "1.1.1.1"] })
```

### Search
```typescript
shodan_search({
  query: "port:22 org:Google",
  limit: 100,
  page: 1
})
```

### Search Statistics
```typescript
search_stats({ query: "product:Apache" })
```

### Organization Lookup
```typescript
organization_lookup({ orgName: "Google" })
```

### Network Lookup
```typescript
network_lookup({ cidr: "8.8.8.0/24" })
```

### Domain Lookup
```typescript
domain_lookup({ domain: "google.com" })
```

### ISP/ASN Lookup
```typescript
isp_lookup({ asn: "AS15169" })
```

### DNS Resolution
```typescript
dns_resolve({ hostname: "google.com" })
```

### Reverse DNS
```typescript
dns_reverse({ ip: "8.8.8.8" })
```

### CVE Lookup
```typescript
cve_lookup({ cveId: "CVE-2017-0144" })
```

### CPE Lookup
```typescript
cpe_lookup({ cpeId: "cpe:2.3:a:apache:http_server:2.4.49" })
```

### CVEs by CPE
```typescript
cves_by_cpe({ vendor: "apache", product: "http_server" })
```

### Product Search
```typescript
product_search({ query: "apache", vendor: "apache" })
```

### Map Search
```typescript
map_search({
  lat1: 40.9176,
  lon1: -74.2591,
  lat2: 40.4774,
  lon2: -73.7004,
  limit: 100
})
```

## Development

### Setup

```bash
git clone https://github.com/brian/shodan-mcp.git
cd shodan-mcp
npm install
```

### Build

```bash
npm run build
```

### Run in Development Mode

```bash
export SHODAN_API_KEY="your-api-key-here"
npm run dev
```

### Type Checking

```bash
npm run typecheck
```

## Docker

### Build

```bash
docker build -t shodan-mcp:latest .
```

### Run

```bash
docker run -e SHODAN_API_KEY="your-api-key-here" shodan-mcp:latest
```

## Rate Limiting

Shodan API has rate limits based on your account tier:
- Free: ~50 requests/minute
- Hobby: ~100 requests/minute
- Team/Enterprise: Higher limits

The server will report rate limit errors appropriately.

## Error Handling

The server implements comprehensive error handling for:
- Invalid API keys
- Rate limiting (429 responses)
- Network errors
- Invalid input parameters (validated with Zod)
- Shodan API errors

All errors are properly formatted according to MCP protocol standards.

## Project Structure

```
shodan-mcp/
├── src/
│   ├── index.ts           # MCP server entry point
│   ├── shodan-client.ts   # Shodan API client
│   └── tools/
│       ├── index.ts       # Export all tools
│       ├── host.ts        # IP lookup, batch lookup
│       ├── search.ts      # Search, stats
│       ├── org.ts         # Organization, network, domain, ISP
│       ├── dns.ts         # DNS, hostnames
│       ├── vuln.ts        # CVE, CPE, products
│       └── map.ts         # Geospatial search
├── package.json
├── tsconfig.json
├── Dockerfile
├── README.md
└── LICENSE
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- [Shodan API](https://developer.shodan.io/) - Network intelligence platform
- [Model Context Protocol](https://modelcontextprotocol.io/) - Standard for AI tool integration

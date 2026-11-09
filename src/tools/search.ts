/**
 * Search-related MCP tools for Shodan
 * Search and statistics queries
 */

import { z } from 'zod';
import type { ShodanClient } from '../shodan-client.js';

interface Tool {
  name: string;
  description: string;
  inputSchema: z.ZodObject<{
    [key: string]: z.ZodTypeAny;
  }>;
}

export const SHODAN_SEARCH_TOOL: Tool = {
  name: 'shodan_search',
  description: `Search Shodan's database of internet-connected devices.

Use Shodan query syntax to find hosts matching specific criteria.
Examples of useful queries:
- "port:22" - hosts with SSH open
- "org:Google" - hosts belonging to Google
- "city:New York" - hosts in New York
- "product:Apache" - hosts running Apache
- "vuln:CVE-2017-0144" - hosts with specific vulnerability
- "os:Linux" - Linux hosts

Query operators:
- port:X - specific port
- org:NAME - organization name
- city:CITY - city name
- country:CC - country code
- product:NAME - product name
- os:NAME - operating system
- vuln:CVE - vulnerability ID
- version:X - version number

Returns up to 1000 matches by default.`,
  inputSchema: z.object({
    query: z.string()
      .min(1)
      .describe('Shodan search query using Shodan query syntax'),
    limit: z.number()
      .min(1)
      .max(1000)
      .default(100)
      .describe('Maximum number of results to return (1-1000)'),
    page: z.number()
      .min(1)
      .default(1)
      .describe('Page number for pagination'),
  }),
};

export const SEARCH_STATS_TOOL: Tool = {
  name: 'search_stats',
  description: `Get statistics and facets for a Shodan search query.

Returns the total count of matching results and breakdowns by various
attributes like country, port, organization, etc.

Useful for understanding the scope of a search without retrieving
all results.`,
  inputSchema: z.object({
    query: z.string()
      .min(1)
      .describe('Shodan search query using Shodan query syntax'),
  }),
};

export async function shodanSearch(
  client: ShodanClient,
  args: { query: string; limit: number; page: number }
): Promise<{ content: unknown[] }> {
  // Current Shodan API: /shodan/host/search. Pagination is either `page` OR
  // `offset`+`limit` (never both), so we derive offset from the requested page.
  const data = await client.request<unknown>('/shodan/host/search', {
    query: args.query.replace(/\s+/g, '|'),
    limit: args.limit,
    offset: (args.page - 1) * args.limit,
  });
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function searchStats(
  client: ShodanClient,
  args: { query: string }
): Promise<{ content: unknown[] }> {
  // Current Shodan API: /shodan/host/count returns the total match count for a query.
  const data = await client.request<unknown>('/shodan/host/count', {
    query: args.query.replace(/\s+/g, '|'),
  });
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

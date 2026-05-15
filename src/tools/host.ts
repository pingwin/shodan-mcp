/**
 * Host-related MCP tools for Shodan
 * IP address lookup and batch operations
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

export const HOST_LOOKUP_TOOL: Tool = {
  name: 'host_lookup',
  description: `Look up a single IP address on Shodan.

Returns detailed information about a host including:
- Open ports and services
- Organization details
- Operating system and product information
- Geolocation data
- Known vulnerabilities
- Hostnames

Use this tool when you need detailed information about a specific IP address.`,
  inputSchema: z.object({
    ip: z.string()
      .ip()
      .describe('The IP address to look up'),
  }),
};

export const HOST_BATCH_LOOKUP_TOOL: Tool = {
  name: 'host_batch_lookup',
  description: `Look up multiple IP addresses in a single request (up to 100 IPs).

Useful for scanning multiple hosts efficiently. Returns a dictionary where
each key is an IP address and the value is either host data or an error/not found.

Maximum 100 IPs per request for optimal performance.`,
  inputSchema: z.object({
    ips: z.array(z.string().ip())
      .max(100)
      .min(1)
      .describe('Array of IP addresses to look up (max 100)'),
  }),
};

export async function hostLookup(
  client: ShodanClient,
  args: { ip: string }
): Promise<{ content: unknown[] }> {
  const data = await client.request<unknown>('/shodan/host/' + args.ip);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function hostBatchLookup(
  client: ShodanClient,
  args: { ips: string[] }
): Promise<{ content: unknown[] }> {
  const data = await client.request<unknown>('/shodan/host/', {
    ip: args.ips.join(','),
  });
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

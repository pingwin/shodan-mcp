/**
 * Organization-related MCP tools for Shodan
 * Organization, network, domain, and ISP lookups
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

export const ORGANIZATION_LOOKUP_TOOL: Tool = {
  name: 'organization_lookup',
  description: `Look up organization information by name.

Returns organization details including:
- ASN number
- CIDR ranges
- Number of hosts
- Sample host IPs
- Organization domain

Use this tool to find all hosts belonging to a specific organization.`,
  inputSchema: z.object({
    orgName: z.string()
      .min(1)
      .describe('Name of the organization to look up'),
  }),
};

export const NETWORK_LOOKUP_TOOL: Tool = {
  name: 'network_lookup',
  description: `Look up network information by CIDR block.

Returns details about a specific network range including:
- ASN information
- Organization details
- IP range boundaries
- Number of hosts in the network

Example CIDRs: '192.168.1.0/24', '8.8.8.0/24'`,
  inputSchema: z.object({
    cidr: z.string()
      .describe('CIDR block to look up (e.g., "192.168.1.0/24")'),
  }),
};

export const DOMAIN_LOOKUP_TOOL: Tool = {
  name: 'domain_lookup',
  description: `Get domain intelligence data.

Returns information about a domain including:
- All IP addresses associated with the domain
- Tags (vulnerabilities, technologies detected)
- Last update timestamp
- ASN and network information

Useful for understanding the attack surface of a domain.`,
  inputSchema: z.object({
    domain: z.string()
      .min(1)
      .describe('Domain name to look up'),
  }),
};

export const ISP_LOOKUP_TOOL: Tool = {
  name: 'isp_lookup',
  description: `Look up ASN (Autonomous System Number) information.

Returns details about an ASN including:
- ASN number
- ISP/organization name
- CIDR ranges
- Number of hosts
- Sample host IPs

You can provide the ASN with or without the 'AS' prefix (e.g., '15169' or 'AS15169').`,
  inputSchema: z.object({
    asn: z.string()
      .min(1)
      .describe('ASN number to look up (with or without "AS" prefix)'),
  }),
};

export async function organizationLookup(
  client: ShodanClient,
  args: { orgName: string }
): Promise<{ content: unknown[] }> {
  const data = await client.request<unknown>(`/org/${encodeURIComponent(args.orgName)}/json`);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function networkLookup(
  client: ShodanClient,
  args: { cidr: string }
): Promise<{ content: unknown[] }> {
  const data = await client.request<unknown>(`/org/${encodeURIComponent(args.cidr)}/json`);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function domainLookup(
  client: ShodanClient,
  args: { domain: string }
): Promise<{ content: unknown[] }> {
  // Current Shodan API: domain intelligence moved to /dns/domain/<domain>.
  const data = await client.request<unknown>(`/dns/domain/${encodeURIComponent(args.domain)}`);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function ispLookup(
  client: ShodanClient,
  args: { asn: string }
): Promise<{ content: unknown[] }> {
  // Normalize to the canonical AS-prefixed form (accept "15169" or "AS15169").
  const asnFormatted = `AS${args.asn.toUpperCase().replace(/^AS/, '')}`;
  const data = await client.request<unknown>(`/org/${asnFormatted}/json`);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

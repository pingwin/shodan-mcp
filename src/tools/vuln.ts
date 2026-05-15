/**
 * Vulnerability-related MCP tools for Shodan
 * CVE, CPE, and product vulnerability lookups
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

export const CVE_LOOKUP_TOOL: Tool = {
  name: 'cve_lookup',
  description: `Look up details for a specific CVE (Common Vulnerabilities and Exposures).

Returns comprehensive information about a vulnerability including:
- CVE ID and description
- CVSS severity score
- Affected CPEs (products)
- References and links
- Publication date

Use this tool to get detailed information about specific vulnerabilities.

Example CVE format: 'CVE-2017-0144'`,
  inputSchema: z.object({
    cveId: z.string()
      .regex(/^CVE-\d{4}-\d{4,}$/)
      .describe('CVE identifier (e.g., "CVE-2017-0144")'),
  }),
};

export const CPE_LOOKUP_TOOL: Tool = {
  name: 'cpe_lookup',
  description: `Look up CPE (Common Platform Enumeration) product information.

CPE is a standardized naming scheme for information technology systems,
components, and applications.

Returns details about a CPE including:
- CPE identifiers (v2.2, v2.3, URI format)
- Vendor, product, and version
- All versions and updates available
- Update count and version count

Example CPE format: 'cpe:/a:apache:http_server' or 'cpe:2.3:a:apache:http_server:2.4.0'`,
  inputSchema: z.object({
    cpeId: z.string()
      .min(1)
      .describe('CPE identifier (e.g., "cpe:/a:apache:http_server" or "cpe:2.3:a:apache:http_server:2.4.0")'),
  }),
};

export const CVES_BY_CPE_TOOL: Tool = {
  name: 'cves_by_cpe',
  description: `Find all CVEs affecting a specific CPE product.

Returns a list of all known vulnerabilities for a given vendor and product.

This is useful for vulnerability assessment and determining what CVEs
affect specific software products.

Example: Find all CVEs for Apache HTTP Server (vendor: 'apache', product: 'http_server').`,
  inputSchema: z.object({
    vendor: z.string()
      .min(1)
      .describe('Vendor name (e.g., "apache", "microsoft", "cisco")'),
    product: z.string()
      .optional()
      .describe('Product name (optional, defaults to all products from vendor)'),
  }),
};

export const PRODUCT_SEARCH_TOOL: Tool = {
  name: 'product_search',
  description: `Search for products in the CPE database.

Search for software products by name or vendor. Returns matching CPEs
with their vendor, product, and version information.

Useful for finding the correct CPE identifier for a product or
discovering products from a specific vendor.`,
  inputSchema: z.object({
    query: z.string()
      .min(1)
      .describe('Search query for product name'),
    vendor: z.string()
      .optional()
      .describe('Optional vendor filter (e.g., "apache", "microsoft")'),
    limit: z.number()
      .min(1)
      .max(100)
      .default(20)
      .describe('Maximum number of results to return (1-100)'),
    page: z.number()
      .min(1)
      .default(1)
      .describe('Page number for pagination'),
  }),
};

export async function cveLookup(
  client: ShodanClient,
  args: { cveId: string }
): Promise<{ content: unknown[] }> {
  const data = await client.request<unknown>(`/shodan/cve/${args.cveId}`);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function cpeLookup(
  client: ShodanClient,
  args: { cpeId: string }
): Promise<{ content: unknown[] }> {
  const data = await client.request<unknown>(
    `/shodan/cpe/${encodeURIComponent(args.cpeId)}`
  );
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function cvesByCpe(
  client: ShodanClient,
  args: { vendor: string; product?: string }
): Promise<{ content: unknown[] }> {
  const cpeString = args.product
    ? `cpe:2.3:a:${args.vendor}:${args.product}`
    : `cpe:2.3:a:${args.vendor}`;

  const data = await client.request<unknown>('/shodan/cve/cpe', {
    cpe: cpeString,
  });
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function productSearch(
  client: ShodanClient,
  args: { query: string; vendor?: string; limit: number; page: number }
): Promise<{ content: unknown[] }> {
  const params: Record<string, string | number> = {
    query: args.query.replace(/\s+/g, '|'),
    limit: args.limit,
    page: args.page,
  };
  if (args.vendor) {
    params.vendor = args.vendor;
  }

  const data = await client.request<unknown>('/shodan/cpe/search', params);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

#!/usr/bin/env node
/**
 * Shodan MCP Server
 * A Model Context Protocol server for Shodan API v1
 *
 * Provides tools for:
 * - Host lookups (single and batch)
 * - Search and statistics
 * - Organization, network, domain, and ISP lookups
 * - DNS resolution
 * - Vulnerability (CVE/CPE) lookups
 * - Geospatial searches
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { zodToJsonSchema } from 'zod-to-json-schema';

import { ShodanClient } from './shodan-client.js';
import * as tools from './tools/index.js';

// Get API key from environment
const API_KEY = process.env.SHODAN_API_KEY;

if (!API_KEY) {
  console.error('Error: SHODAN_API_KEY environment variable is required');
  console.error('Please set it before running this server, e.g.:');
  console.error('  export SHODAN_API_KEY="your-api-key-here"');
  process.exit(1);
}

// Create Shodan client
const shodanClient = new ShodanClient({
  apiKey: API_KEY,
  userAgent: 'ShodanMCP/1.0.0',
});

// Generic tool handler - accepts any arguments (validated by zod at runtime)
type ToolHandler = (client: ShodanClient, args: unknown) => Promise<{ content: unknown[] }>;

// All available tools (tool definition -> handler function mapping)
const TOOL_HANDLERS: Record<string, ToolHandler> = {
  host_lookup: tools.hostLookup as ToolHandler,
  host_batch_lookup: tools.hostBatchLookup as ToolHandler,
  shodan_search: tools.shodanSearch as ToolHandler,
  search_stats: tools.searchStats as ToolHandler,
  organization_lookup: tools.organizationLookup as ToolHandler,
  network_lookup: tools.networkLookup as ToolHandler,
  domain_lookup: tools.domainLookup as ToolHandler,
  isp_lookup: tools.ispLookup as ToolHandler,
  map_search: tools.mapSearch as ToolHandler,
  cve_lookup: tools.cveLookup as ToolHandler,
  cpe_lookup: tools.cpeLookup as ToolHandler,
  cves_by_cpe: tools.cvesByCpe as ToolHandler,
  product_search: tools.productSearch as ToolHandler,
  dns_resolve: tools.dnsResolve as ToolHandler,
  dns_reverse: tools.dnsReverse as ToolHandler,
};

// All tool definitions
const TOOLS = [
  tools.HOST_LOOKUP_TOOL,
  tools.HOST_BATCH_LOOKUP_TOOL,
  tools.SHODAN_SEARCH_TOOL,
  tools.SEARCH_STATS_TOOL,
  tools.ORGANIZATION_LOOKUP_TOOL,
  tools.NETWORK_LOOKUP_TOOL,
  tools.DOMAIN_LOOKUP_TOOL,
  tools.ISP_LOOKUP_TOOL,
  tools.MAP_SEARCH_TOOL,
  tools.CVE_LOOKUP_TOOL,
  tools.CPE_LOOKUP_TOOL,
  tools.CVES_BY_CPE_TOOL,
  tools.PRODUCT_SEARCH_TOOL,
  tools.DNS_RESOLVE_TOOL,
  tools.DNS_REVERSE_TOOL,
];

// Create MCP server
const server = new Server(
  {
    name: 'shodan-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle tool listing request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: TOOLS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: zodToJsonSchema(tool.inputSchema),
    })),
  };
});

// Handle tool call request
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  const handler = TOOL_HANDLERS[name];
  if (!handler) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Unknown tool: ${name}`
    );
  }

  try {
    // Parse and validate arguments using zod schema
    const toolDef = TOOLS.find((t) => t.name === name);
    if (!toolDef) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Tool definition not found: ${name}`
      );
    }

    // Parse arguments using zod schema
    const parsedArgs = toolDef.inputSchema.parse(args);

    // Execute the tool handler
    const result = await handler(shodanClient, parsedArgs);

    return {
      content: result.content,
    };
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }

    // Handle zod validation errors
    if (error instanceof Error && error.name === 'ZodError') {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Invalid arguments for tool ${name}: ${error.message}`
      );
    }

    // Handle Shodan API errors
    if (error instanceof Error) {
      if (error.message.includes('Shodan API error')) {
        throw new McpError(
          ErrorCode.InternalError,
          error.message
        );
      }

      // Handle rate limiting
      if (error.message.includes('429')) {
        throw new McpError(
          ErrorCode.InternalError,
          'Rate limit exceeded. Please wait before making more requests.'
        );
      }
    }

    throw new McpError(
      ErrorCode.InternalError,
      `Error executing tool ${name}: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Shodan MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error running server:', error);
  process.exit(1);
});

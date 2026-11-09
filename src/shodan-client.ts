/**
 * Shodan API Client
 * Handles all API communication with Shodan's REST API
 */

const API_BASE_URL = 'https://api.shodan.io';

export interface ShodanClientOptions {
  apiKey: string;
  userAgent?: string;
}

export class ShodanClient {
  private apiKey: string;
  private userAgent: string;

  constructor(options: ShodanClientOptions) {
    this.apiKey = options.apiKey;
    this.userAgent = options.userAgent || 'ShodanMCP/1.0.0';
  }

  private buildUrl(endpoint: string, params: Record<string, string | number>): string {
    const url = new URL(`${API_BASE_URL}${endpoint}`);
    url.searchParams.append('key', this.apiKey);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.append(key, String(value));
    }
    return url.toString();
  }

  async request<T>(endpoint: string, params: Record<string, string | number> = {}): Promise<T> {
    const url = this.buildUrl(endpoint, params);

    const response = await fetch(url, {
      headers: {
        'User-Agent': this.userAgent,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      let errorMessage = `Shodan API error: ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json() as { error?: string };
        errorMessage = errorData.error || errorMessage;
      } catch {
        // Use default error message
      }
      throw new Error(errorMessage);
    }

    return response.json() as Promise<T>;
  }

  // Host endpoint methods

  /**
   * Get detailed information about a host
   */
  async hostLookup(ip: string): Promise<HostData> {
    return this.request(`/shodan/host/${ip}/json`);
  }

  /**
   * Get detailed information about multiple hosts (up to 100)
   */
  async hostBatchLookup(hosts: string[]): Promise<BatchHostData> {
    return this.request(`/shodan/host/${hosts.join(',')}`);
  }

  // Search endpoint methods

  /**
   * Search for hosts matching a query
   */
  async search(query: string, page = 1, pageSize = 1000): Promise<SearchResults> {
    return this.request('/shodan/host/search', {
      query: query.replace(/\s+/g, '|'), // Shodan requires OR format
      limit: pageSize,
      offset: (page - 1) * pageSize,
    });
  }

  /**
   * Get statistics/facets for a search query
   */
  async searchStats(query: string, facets?: string[]): Promise<SearchStats> {
    const params: Record<string, string | number> = { query: query.replace(/\s+/g, '|') };
    if (facets && facets.length > 0) {
      params.facets = facets.join('|');
    }
    return this.request('/shodan/host/count', params);
  }

  // Organization endpoint methods

  /**
   * Get organization information by name
   */
  async organizationLookup(name: string): Promise<OrganizationData> {
    return this.request(`/org/${encodeURIComponent(name)}/json`);
  }

  /**
   * Get network information by CIDR
   */
  async networkLookup(cidr: string): Promise<NetworkData> {
    return this.request(`/org/${encodeURIComponent(cidr)}/json`);
  }

  /**
   * Get domain intelligence
   */
  async domainLookup(domain: string): Promise<DomainData> {
    return this.request(`/dns/domain/${domain}`);
  }

  /**
   * Get ASN/ISP information
   */
  async ispLookup(asn: string): Promise<ASNData> {
    return this.request(`/org/AS${asn}/json`);
  }

  // DNS endpoint methods

  /**
   * Forward DNS lookup (hostname -> IP)
   */
  async dnsResolve(hostname: string): Promise<DNSResolveData> {
    return this.request(`/dns/resolve/${hostname}/json`);
  }

  /**
   * Reverse DNS lookup (IP -> hostname)
   */
  async dnsReverse(ip: string): Promise<DNSReverseData> {
    return this.request(`/dns/reverse/${ip}/json`);
  }

  // Vulnerability endpoint methods

  /**
   * Get CVE details
   */
  async cveLookup(cveId: string): Promise<CVEData> {
    return this.request(`/shodan/cve/${cveId}`);
  }

  /**
   * Get CPE product information
   */
  async cpeLookup(cpeId: string): Promise<CPEData> {
    return this.request(`/shodan/cpe/${cpeId}`);
  }

  /**
   * Get CVEs for a specific CPE
   */
  async cvesByCpe(vendor: string, product?: string): Promise<CVEByCPEResult> {
    const cpeString = product ? `cpe:2.3:a:${vendor}:${product}` : `cpe:2.3:a:${vendor}`;
    return this.request(`/shodan/cve/cpe`, { cpe: cpeString });
  }

  /**
   * Search for products
   */
  async productSearch(query: string, vendor?: string, page = 1, pageSize = 100): Promise<ProductSearchResults> {
    const params: Record<string, string | number> = {
      query: query.replace(/\s+/g, '|'),
      page,
      limit: pageSize,
    };
    if (vendor) {
      params.vendor = vendor;
    }
    return this.request('/shodan/cpe/search', params);
  }

  // Map endpoint methods

  /**
   * Search for hosts in a geospatial area
   */
  async mapSearch(lat1: number, lon1: number, lat2: number, lon2: number, limit = 1000): Promise<MapSearchResults> {
    return this.request('/shodan/map/search', {
      bounds: `${lat1},${lon1},${lat2},${lon2}`,
      limit,
    });
  }
}

// TypeScript interfaces for Shodan API responses

export interface HostData {
  ip_str: string;
  port: number;
  org: string;
  os?: string;
  product?: string;
  product_version?: string;
  transport?: string;
  hostnames?: string[];
  location?: {
    country_name: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    geolocation?: {
      latitude: number;
      longitude: number;
    };
  };
  vulns?: string[];
  tags?: string[];
  data?: string;
  timestamp?: string;
  ssl?: {
    cert?: {
      [key: string]: unknown;
    };
  };
  [key: string]: unknown;
}

export interface BatchHostData {
  [key: string]: HostData | 'not found' | 'error';
}

export interface SearchResults {
  total: number;
  matches: HostData[];
  pagination?: {
    offset: number;
    limit: number;
    total: number;
  };
}

export interface SearchStats {
  total: number;
  facets?: {
    [key: string]: {
      [value: string]: number;
    };
  };
}

export interface OrganizationData {
  asn: string;
  cidr: string;
  domain: string;
  host_count: number;
  hosts: string[];
  name: string;
  Org: string;
}

export interface NetworkData extends OrganizationData {
  ip_range?: {
    start: string;
    end: string;
  };
  netmask: string;
}

export interface DomainData {
  domain: string;
  hosts: string[];
  tags: string[];
  last_update: string;
  asn?: string;
  netmask?: string;
}

export interface ASNData {
  asn: string;
  cidr: string;
  domain: string;
  host_count: number;
  hosts: string[];
  name: string;
  Org: string;
}

export interface DNSResolveData {
  ip?: string;
  timestamp?: string;
}

export interface DNSReverseData {
  hostname?: string;
  hostnames?: string[];
  timestamp?: string;
}

export interface CVEData {
  id: string;
  cves?: string[];
  description?: string;
  cvss?: number;
  severity?: string;
  score?: number;
  published?: string;
  references?: string[];
  cpe?: string[];
}

export interface CPEData {
  cpe: string;
  cpe23: string;
  cpe23uri: string;
  part: string;
  vendor: string;
  product: string;
  version: string;
  update?: string;
  edition?: string;
  language?: string;
  sw_edition?: string;
  target_sw?: string;
  target_hw?: string;
  other?: string;
  update_count?: number;
  version_count?: number;
}

export interface CVEByCPEResult {
  cpe: string;
  cves: string[];
}

export interface ProductSearchResults {
  total: number;
  results: CPEData[];
}

export interface MapSearchResults {
  total: number;
  matches: HostData[];
}

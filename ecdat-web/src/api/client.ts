import { readJson } from './response';
import type {
  Asset,
  Scan,
  PolicyResult,
  PQCAdvisory,
  PaginatedResult,
} from './types';

const API_BASE = '/api/v1';

const handleResponse = readJson;

function buildQuery(params?: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams();
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') {
        q.append(key, String(value));
      }
    }
  }
  return q.toString();
}

// API Client Methods — all calls hit the real backend; failures throw.
export const apiClient = {
  async getScans(): Promise<Scan[]> {
    const data = await handleResponse<Scan[]>(
      await fetch(`${API_BASE}/workspace/scans`, { headers: {} })
    );
    return data;
  },

  async getAssets(params?: {
    page?: number;
    pageSize?: number;
    algorithm?: string;
    confidence?: string;
  }): Promise<PaginatedResult<Asset>> {
    const query = buildQuery({
      page: params?.page,
      page_size: params?.pageSize,
      algorithm: params?.algorithm,
      confidence: params?.confidence,
    });
    const data = await handleResponse<PaginatedResult<Asset>>(
      await fetch(`${API_BASE}/workspace/assets${query ? `?${query}` : ''}`, {
        headers: {},
      }),
    );
    return data;
  },

  async getAllAssets(): Promise<Asset[]> {
    const first = await this.getAssets({ page: 1, pageSize: 100 });
    const items = [...first.items];
    for (let page = 2; page <= first.pages; page++) {
      const next = await this.getAssets({ page, pageSize: 100 });
      items.push(...next.items);
    }
    return items;
  },

  async getPolicies(): Promise<PolicyResult[]> {
    return handleResponse<PolicyResult[]>(
      await fetch(`${API_BASE}/workspace/policies`, { headers: {} })
    );
  },

  async getAdvisories(): Promise<PQCAdvisory[]> {
    return handleResponse<PQCAdvisory[]>(
      await fetch(`${API_BASE}/advisories`, { headers: {} })
    );
  },
};

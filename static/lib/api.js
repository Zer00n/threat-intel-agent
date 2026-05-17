const API = {
  async get(path) {
    const resp = await fetch(path);
    if (!resp.ok) throw new Error(`GET ${path}: ${resp.status}`);
    return resp.json();
  },

  async post(path, body) {
    const resp = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `POST ${path}: ${resp.status}`);
    }
    return resp.json();
  },

  async put(path, body) {
    const resp = await fetch(path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error(`PUT ${path}: ${resp.status}`);
    return resp.json();
  },

  async patch(path, body) {
    const resp = await fetch(path, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || `PATCH ${path}: ${resp.status}`);
    }
    return resp.json();
  },

  async del(path) {
    const resp = await fetch(path, { method: 'DELETE' });
    if (!resp.ok) throw new Error(`DELETE ${path}: ${resp.status}`);
    return resp.json();
  },

  analyze: (query, tlp = 'GREEN', forceIntent = null) =>
    API.post('/analyze', { query, tlp, force_intent: forceIntent }),

  stop: (taskId) => API.post(`/analyze/${taskId}/stop`),

  switchIntent: (taskId, intent) => API.post(`/analyze/${taskId}/switch_intent`, { intent }),

  history: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return API.get(`/history${q ? '?' + q : ''}`);
  },

  historyDetail: (id) => API.get(`/history/${id}`),

  deleteHistory: (id) => API.del(`/history/${id}`),

  batchDeleteHistory: (ids) => API.post('/history/batch_delete', { ids }),

  sourcesHealth: () => API.get('/sources/health'),

  assetSpaces: () => API.get('/api/asset-spaces'),

  createAssetSpace: (data) => API.post('/api/asset-spaces', data),

  analyzeAssetSpace: (spaceId) => API.post(`/api/asset-spaces/${spaceId}/analyze`),

  assets: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return API.get(`/api/assets${q ? '?' + q : ''}`);
  },

  assetDetail: (id) => API.get(`/api/assets/${id}`),

  importAssetsCsvText: (data) => API.post('/api/assets/import/csv-text', data),

  importAssetsJsonText: (data) => API.post('/api/assets/import/json-text', data),

  importAssetsNmapText: (data) => API.post('/api/assets/import/nmap-text', data),

  identifyService: (hostId, serviceId) => API.post(`/api/assets/${hostId}/services/${serviceId}/identify`),

  identifyHost: (hostId) => API.post(`/api/assets/${hostId}/identify`),

  updateAssetCveMatch: (matchId, data) => API.patch(`/api/asset-cve-matches/${matchId}`, data),

  testSource: (name) => API.post(`/sources/test/${name}`),

  settings: () => API.get('/settings'),

  updateSettings: (data) => API.put('/settings', data),

  stats: () => API.get('/stats'),

  diffAnalyses: (id, compareId) => API.get(`/history/${id}/diff/${compareId}`),

  trustedSources: () => API.get('/settings/trusted_sources'),

  addTrustedSource: (domain, note) => API.post('/settings/trusted_sources', { domain, note }),

  deleteTrustedSource: (domain) => API.del(`/settings/trusted_sources/${domain}`),

  download: (path) => {
    const a = document.createElement('a');
    a.href = path;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
  },
};

export default API;

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

  async del(path) {
    const resp = await fetch(path, { method: 'DELETE' });
    if (!resp.ok) throw new Error(`DELETE ${path}: ${resp.status}`);
    return resp.json();
  },

  analyze: (query, tlp = 'GREEN', forceIntent = null) =>
    API.post('/analyze', { query, tlp, force_intent: forceIntent }),

  stop: (taskId) => API.post(`/analyze/${taskId}/stop`),

  history: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return API.get(`/history${q ? '?' + q : ''}`);
  },

  historyDetail: (id) => API.get(`/history/${id}`),

  deleteHistory: (id) => API.del(`/history/${id}`),

  sourcesHealth: () => API.get('/sources/health'),

  testSource: (name) => API.post(`/sources/test/${name}`),

  settings: () => API.get('/settings'),

  updateSettings: (data) => API.put('/settings', data),

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

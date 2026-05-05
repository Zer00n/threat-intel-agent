class Router {
  constructor() {
    this.routes = {};
    this.current = null;
    window.addEventListener('hashchange', () => this._resolve());
  }

  on(path, handler) {
    this.routes[path] = handler;
    return this;
  }

  start() {
    this._resolve();
  }

  navigate(path) {
    window.location.hash = path;
  }

  _resolve() {
    const hash = window.location.hash.slice(1) || '/';
    let matched = false;

    for (const [pattern, handler] of Object.entries(this.routes)) {
      const regex = new RegExp('^' + pattern.replace(/:\w+/g, '([^/]+)') + '$');
      const match = hash.match(regex);
      if (match) {
        const params = match.slice(1);
        this.current = { path: hash, pattern, params };
        handler(...params);
        matched = true;
        break;
      }
    }

    if (!matched && this.routes['*']) {
      this.routes['*']();
    }

    // Update nav links
    document.querySelectorAll('.nav-link').forEach(link => {
      const page = link.dataset.page;
      const isActive =
        (page === 'workspace' && (hash === '/' || hash === '')) ||
        (page === 'history' && hash.startsWith('/history')) ||
        (page === 'sources' && hash.startsWith('/sources')) ||
        (page === 'settings' && hash.startsWith('/settings'));
      link.classList.toggle('active', isActive);
    });
  }
}

export const router = new Router();

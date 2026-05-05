export class TIEventSource {
  constructor(taskId, handlers = {}) {
    this.taskId = taskId;
    this.handlers = handlers;
    this.lastEventId = null;
    this.reconnectAttempts = 0;
    this.maxReconnectDelay = 30000;
    this._aborted = false;
    this._controller = null;
    this._connect();
  }

  _connect() {
    if (this._aborted) return;
    this._controller = new AbortController();
    const url = this.lastEventId
      ? `/stream/${this.taskId}?last_event_id=${this.lastEventId}`
      : `/stream/${this.taskId}`;

    fetch(url, { signal: this._controller.signal })
      .then(resp => {
        if (!resp.ok) throw new Error(`SSE ${resp.status}`);
        this.reconnectAttempts = 0;
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        const read = () => {
          reader.read().then(({ done, value }) => {
            if (done) {
              this._scheduleReconnect();
              return;
            }
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop();

            let eventType = '';
            let eventData = '';
            let eventId = null;

            for (const line of lines) {
              if (line.startsWith('id: ')) {
                eventId = parseInt(line.slice(4));
              } else if (line.startsWith('event: ')) {
                eventType = line.slice(7);
              } else if (line.startsWith('data: ')) {
                eventData = line.slice(6);
              } else if (line === '') {
                if (eventType && eventData) {
                  this.lastEventId = eventId || this.lastEventId;
                  this._dispatch(eventType, eventData);
                }
                eventType = '';
                eventData = '';
                eventId = null;
              }
            }
            read();
          }).catch(err => {
            if (!this._aborted) this._scheduleReconnect();
          });
        };
        read();
      })
      .catch(err => {
        if (!this._aborted) this._scheduleReconnect();
      });
  }

  _scheduleReconnect() {
    if (this._aborted) return;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), this.maxReconnectDelay);
    this.reconnectAttempts++;
    setTimeout(() => this._connect(), delay);
  }

  _dispatch(eventType, dataStr) {
    try {
      const data = JSON.parse(dataStr);
      const handler = this.handlers[eventType] || this.handlers['*'];
      if (handler) handler(data, eventType);
    } catch (e) {
      console.error('SSE parse error:', e);
    }
  }

  abort() {
    this._aborted = true;
    if (this._controller) this._controller.abort();
  }
}

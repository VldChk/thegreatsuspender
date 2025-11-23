const Logger = {
  async log(level, message, data = null) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data: data instanceof Error ? { message: data.message, stack: data.stack } : data,
    };
    console[level](message, data || '');

    try {
      const stored = await chrome.storage.local.get('logs');
      const logs = stored.logs || [];
      logs.push(entry);
      if (logs.length > 1000) {
        logs.shift();
      }
      await chrome.storage.local.set({ logs });
    } catch (err) {
      console.error('Failed to save log', err);
    }
  },
  info(message, data) { this.log('info', message, data); },
  warn(message, data) { this.log('warn', message, data); },
  error(message, data) { this.log('error', message, data); }
};

export default Logger;

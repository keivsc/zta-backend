class Logger {
  constructor(filename) {
    this.filename = filename;
    this.Types = {
      INFO: '[INFO] ',
      WARN: '[WARN] ',
      ERROR: '[ERROR] '
    };
    
    // ANSI color codes
    this.Colors = {
      RESET: '\x1b[0m',
      INFO: '\x1b[36m',   // Cyan
      WARN: '\x1b[33m',   // Yellow
      ERROR: '\x1b[31m',  // Red
    };
  }

  log(type, message) {
    const timestamp = new Date().toISOString();
    const color = this.Colors[type] || this.Colors.INFO;
    const typeLabel = this.Types[type] || '[INFO] ';
    
    console.log(`${color} [${timestamp}] | ${typeLabel}${message}${this.Colors.RESET}`);
  }

  info(message) {
    this.log('INFO', message);
  }

  warn(message) {
    this.log('WARN', message);
  }

  error(message) {
    this.log('ERROR', message);
  }
}

export default Logger;
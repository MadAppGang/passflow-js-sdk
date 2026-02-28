/**
 * Logger interface for Passflow services
 */
export interface Logger {
  error(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  debug(message: string, ...args: unknown[]): void;
}

/**
 * Default console logger implementation
 */
export class ConsoleLogger implements Logger {
  error(message: string, ...args: unknown[]): void {
    // biome-ignore lint/suspicious/noConsole: <explanation>
    console.error(message, ...args);
  }

  warn(message: string, ...args: unknown[]): void {
    // biome-ignore lint/suspicious/noConsole: <explanation>
    console.warn(message, ...args);
  }

  info(message: string, ...args: unknown[]): void {
    // biome-ignore lint/suspicious/noConsole: <explanation>
    console.info(message, ...args);
  }

  debug(message: string, ...args: unknown[]): void {
    // biome-ignore lint/suspicious/noConsole: <explanation>
    console.debug(message, ...args);
  }
}

/**
 * Get the default logger
 * @returns Default logger instance
 */
export function getDefaultLogger(): Logger {
  return new ConsoleLogger();
}

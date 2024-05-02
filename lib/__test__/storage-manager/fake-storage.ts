export class FakeStorage {
  data = new Map<string, string>();

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }

  getItem(key: string): string | null {
    return this.data.get(key) || null;
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }
}

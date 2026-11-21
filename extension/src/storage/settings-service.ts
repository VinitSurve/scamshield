import { DEFAULT_SETTINGS, UserSettings } from '../types/settings';
import { logger } from '../utils/logger';

const SETTINGS_STORAGE_KEY = 'scamshield_user_settings_v1';

export class SettingsService {
  private static cachedSettings: UserSettings = { ...DEFAULT_SETTINGS };
  private static isInitialized = false;

  static async getSettings(): Promise<UserSettings> {
    if (this.isInitialized) {
      return this.cachedSettings;
    }

    this.isInitialized = true;

    try {
      const data = await chrome.storage.local.get(SETTINGS_STORAGE_KEY);
      if (data && data[SETTINGS_STORAGE_KEY]) {
        this.cachedSettings = {
          ...DEFAULT_SETTINGS,
          ...data[SETTINGS_STORAGE_KEY],
        };
      } else {
        this.cachedSettings = { ...DEFAULT_SETTINGS };
        await chrome.storage.local.set({ [SETTINGS_STORAGE_KEY]: this.cachedSettings });
      }
    } catch (err) {
      logger.warn('Failed to load settings from storage, using defaults:', err);
      this.cachedSettings = { ...DEFAULT_SETTINGS };
    }

    return this.cachedSettings;
  }

  static async saveSettings(newSettings: Partial<UserSettings>): Promise<UserSettings> {
    const current = this.isInitialized ? this.cachedSettings : await this.getSettings();
    const updated: UserSettings = {
      ...current,
      ...newSettings,
    };

    try {
      await chrome.storage.local.set({ [SETTINGS_STORAGE_KEY]: updated });
      this.cachedSettings = updated;
      this.isInitialized = true;
      logger.info('Settings successfully saved');
    } catch (err) {
      logger.error('Failed to save settings:', err);
      throw err;
    }

    return updated;
  }

  static async isDomainWhitelisted(domain: string): Promise<boolean> {
    const settings = await this.getSettings();
    const normalized = domain.toLowerCase().trim();
    return settings.whitelistedDomains.some(
      (w) => w.toLowerCase() === normalized || normalized.endsWith(`.${w.toLowerCase()}`)
    );
  }

  static async addDomainToWhitelist(domain: string): Promise<UserSettings> {
    const settings = await this.getSettings();
    const normalized = domain.toLowerCase().trim();
    if (!settings.whitelistedDomains.includes(normalized)) {
      const updated = [...settings.whitelistedDomains, normalized];
      return this.saveSettings({ whitelistedDomains: updated });
    }
    return settings;
  }

  static async removeDomainFromWhitelist(domain: string): Promise<UserSettings> {
    const settings = await this.getSettings();
    const normalized = domain.toLowerCase().trim();
    const updated = settings.whitelistedDomains.filter((d) => d.toLowerCase() !== normalized);
    return this.saveSettings({ whitelistedDomains: updated });
  }

  static async resetSettings(): Promise<UserSettings> {
    this.cachedSettings = { ...DEFAULT_SETTINGS };
    this.isInitialized = true;
    await chrome.storage.local.set({ [SETTINGS_STORAGE_KEY]: this.cachedSettings });
    return this.cachedSettings;
  }
}

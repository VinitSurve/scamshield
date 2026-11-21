import { SupportedLanguage } from '../types/settings';
import { en } from './en';
import { hi } from './hi';
import { mr } from './mr';

const translations: Record<SupportedLanguage, typeof en> = {
  en,
  hi,
  mr,
};

export function getTranslation(lang: SupportedLanguage = 'en'): typeof en {
  return translations[lang] || translations.en;
}

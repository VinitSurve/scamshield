import { describe, it, expect } from 'vitest';
import { getTranslation } from '../src/i18n';

describe('Internationalization & Multilingual Strategy', () => {
  it('loads English translation baseline by default', () => {
    const t = getTranslation('en');
    expect(t.appTitle).toBe('ScamShield');
    expect(t.tagline).toBe('Think Before You Click');
    expect(t.backToSafety).toBe('Back to Safety');
  });

  it('loads Hindi translations correctly', () => {
    const t = getTranslation('hi');
    expect(t.tagline).toBe('क्लिक करने से पहले सोचें');
    expect(t.backToSafety).toBe('सुरक्षित वापस जाएं');
    expect(t.statusProtected).toBe('सुरक्षित और सत्यापित');
  });

  it('loads Marathi translations correctly', () => {
    const t = getTranslation('mr');
    expect(t.tagline).toBe('क्लिक करण्यापूर्वी विचार करा');
    expect(t.backToSafety).toBe('सुरक्षित मागे जा');
    expect(t.warningTitle).toBe('फसवणूक करणारी साइट ब्लॉक केली');
  });

  it('falls back to English when an unsupported language code is provided', () => {
    const t = getTranslation('fr' as any);
    expect(t.appTitle).toBe('ScamShield');
    expect(t.tagline).toBe('Think Before You Click');
  });
});

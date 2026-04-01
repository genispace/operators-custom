import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import HttpBackend from 'i18next-http-backend';

const STORAGE_KEY = 'language';

function initialLanguage(): string {
  if (typeof window === 'undefined') return 'zh-CN';
  try {
    const s = localStorage.getItem(STORAGE_KEY);
    if (s === 'en-US' || s === 'zh-CN') return s;
  } catch {
    /* ignore */
  }
  return 'zh-CN';
}

void i18n
  .use(HttpBackend)
  .use(initReactI18next)
  .init({
    lng: initialLanguage(),
    fallbackLng: 'zh-CN',
    supportedLngs: ['zh-CN', 'en-US'],
    ns: ['playground'],
    defaultNS: 'playground',
    backend: {
      loadPath: '/locales/{{lng}}/{{ns}}.json'
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false }
  })
  .then(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = i18n.language.startsWith('zh') ? 'zh-CN' : 'en';
    }
  });

i18n.on('languageChanged', (lng) => {
  if (typeof document !== 'undefined') {
    document.documentElement.lang = lng.startsWith('zh') ? 'zh-CN' : 'en';
  }
  try {
    localStorage.setItem(STORAGE_KEY, lng);
  } catch {
    /* ignore */
  }
});

export default i18n;

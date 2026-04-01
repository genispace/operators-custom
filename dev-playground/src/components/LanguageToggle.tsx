import type { MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';

/**
 * 与 PublicHeader 一致：Globe + 目标语言简写（当前为中文时显示 EN，为英文时显示「中」）。
 */
export function LanguageToggle({ className = '' }: { className?: string }) {
  const { i18n, t } = useTranslation('playground');

  const isZh = i18n.language.startsWith('zh');

  const handleClick = (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    void i18n.changeLanguage(isZh ? 'en-US' : 'zh-CN');
  };

  return (
    <button
      type="button"
      onClick={handleClick}
      className={`nav-lang-btn flex items-center gap-1.5 rounded-g-sm px-2 py-2 text-sm text-g-text transition-colors ${className}`}
      title={t('change_language', 'Change language')}
    >
      <GlobeIcon className="h-5 w-5 shrink-0" aria-hidden />
      <span>{isZh ? t('language.en_short', 'EN') : t('language.zh_short', '中')}</span>
    </button>
  );
}

function GlobeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}

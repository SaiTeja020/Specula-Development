import { useState } from 'react';
import './review-content.css';

export default function CodeBlock({ value, language = 'text', caption = 'Recorded output' }) {
  const [copyState, setCopyState] = useState('');
  let content = typeof value === 'string' ? value : JSON.stringify(value, null, 2) ?? '';
  if (language === 'json' && typeof value === 'string') {
    try {
      const parsed = JSON.parse(value, (_key, item) => {
        if (typeof item === 'number' && (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item)))) {
          throw new Error('Preserve source numeric precision');
        }
        return item;
      });
      content = JSON.stringify(parsed, null, 2);
    } catch { /* Keep non-JSON or unsafe numeric source output intact. */ }
  }
  async function copy() {
    try {
      await navigator.clipboard.writeText(content);
      setCopyState('Copied');
    } catch { setCopyState('Select the text to copy'); }
  }
  return <figure className="code-panel" data-language={language}>
    <figcaption><span>{caption}</span><span className="code-language">{language}</span>
      <button type="button" className="secondary-btn code-copy" onClick={copy} aria-label={`Copy ${caption}`}>Copy</button>
    </figcaption>
    <pre tabIndex={0} aria-label={caption}><code>{content}</code></pre>
    {copyState && <p className="code-copy-status" role="status">{copyState}</p>}
  </figure>;
}

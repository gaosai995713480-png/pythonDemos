/**
 * 通用主题切换器 — 在子页面中引入即可使用
 * 用法：在 <body> 内添加 <script src="theme-switcher.js"></script>
 * 前提：页面需要有一个 .top-bar 容器
 */
(function () {
  const THEMES = [
    {
      name: '春樱', emoji: '🌸',
      color: 'linear-gradient(135deg, #ee7752, #e73c7e)',
      vars: {
        '--primary': '#ff6b9d', '--secondary': '#c44569', '--accent': '#ffc048',
        '--bg-grad-1': '#ee7752', '--bg-grad-2': '#e73c7e',
        '--bg-grad-3': '#23a6d5', '--bg-grad-4': '#23d5ab',
      }
    },
    {
      name: '星空', emoji: '✨',
      color: 'linear-gradient(135deg, #0f0c29, #302b63)',
      vars: {
        '--primary': '#a78bfa', '--secondary': '#7c3aed', '--accent': '#f9a8d4',
        '--bg-grad-1': '#0f0c29', '--bg-grad-2': '#302b63',
        '--bg-grad-3': '#24243e', '--bg-grad-4': '#0f0c29',
      }
    },
    {
      name: '海边', emoji: '🌊',
      color: 'linear-gradient(135deg, #1cb5e0, #000851)',
      vars: {
        '--primary': '#38bdf8', '--secondary': '#0284c7', '--accent': '#fbbf24',
        '--bg-grad-1': '#1cb5e0', '--bg-grad-2': '#000851',
        '--bg-grad-3': '#0ea5e9', '--bg-grad-4': '#0369a1',
      }
    },
    {
      name: '雪夜', emoji: '❄️',
      color: 'linear-gradient(135deg, #e6dada, #274046)',
      vars: {
        '--primary': '#94a3b8', '--secondary': '#475569', '--accent': '#e2e8f0',
        '--bg-grad-1': '#e6dada', '--bg-grad-2': '#274046',
        '--bg-grad-3': '#536976', '--bg-grad-4': '#292e49',
      }
    }
  ];

  // 注入 CSS
  const style = document.createElement('style');
  style.textContent = `
    .ts-wrap { position: relative; margin-left: auto; }
    .ts-btn {
      width: 36px; height: 36px; border-radius: 10px; border: none;
      background: rgba(255,255,255,0.1); color: #fff; font-size: 18px;
      cursor: pointer; display: flex; align-items: center; justify-content: center;
      border: 1px solid rgba(255,255,255,0.15); transition: all 0.2s;
    }
    .ts-btn:hover { background: rgba(255,255,255,0.2); transform: scale(1.05); }
    .ts-dropdown {
      position: absolute; top: calc(100% + 8px); right: 0;
      background: rgba(20,20,30,0.92); backdrop-filter: blur(20px);
      border: 1px solid rgba(255,255,255,0.15); border-radius: 14px;
      padding: 10px; display: flex; gap: 8px;
      opacity: 0; pointer-events: none; transform: translateY(-6px);
      transition: all 0.2s ease; z-index: 50;
    }
    .ts-dropdown.is-open { opacity: 1; pointer-events: auto; transform: translateY(0); }
    .ts-swatch {
      width: 36px; height: 36px; border-radius: 10px; border: 2px solid transparent;
      cursor: pointer; transition: all 0.2s; position: relative;
    }
    .ts-swatch:hover { transform: scale(1.12); }
    .ts-swatch.is-active { border-color: #fff; box-shadow: 0 0 12px rgba(255,255,255,0.3); }
    .ts-swatch::after {
      content: attr(data-emoji); position: absolute; inset: 0;
      display: flex; align-items: center; justify-content: center; font-size: 16px;
    }
  `;
  document.head.appendChild(style);

  // 构建 DOM
  const topBar = document.querySelector('.top-bar');
  if (!topBar) return;

  const wrap = document.createElement('div');
  wrap.className = 'ts-wrap';

  const btn = document.createElement('button');
  btn.className = 'ts-btn';
  btn.type = 'button';
  btn.textContent = '🎨';
  btn.title = '切换主题';

  const dropdown = document.createElement('div');
  dropdown.className = 'ts-dropdown';

  // 读取当前主题名
  let currentName = '春樱';
  try {
    const s = localStorage.getItem('love_theme');
    if (s) currentName = JSON.parse(s).name || '春樱';
  } catch(e) {}

  THEMES.forEach(theme => {
    const swatch = document.createElement('div');
    swatch.className = 'ts-swatch';
    if (theme.name === currentName) swatch.classList.add('is-active');
    swatch.style.background = theme.color;
    swatch.dataset.emoji = theme.emoji;
    swatch.title = theme.name;
    swatch.addEventListener('click', () => {
      // 应用 CSS 变量
      Object.entries(theme.vars).forEach(([k, v]) =>
        document.documentElement.style.setProperty(k, v)
      );
      // 保存
      localStorage.setItem('love_theme', JSON.stringify({ name: theme.name, vars: theme.vars }));
      // 更新 active
      dropdown.querySelectorAll('.ts-swatch').forEach(s => s.classList.remove('is-active'));
      swatch.classList.add('is-active');
      dropdown.classList.remove('is-open');
    });
    dropdown.appendChild(swatch);
  });

  wrap.appendChild(btn);
  wrap.appendChild(dropdown);
  topBar.appendChild(wrap);

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('is-open');
  });
  document.addEventListener('click', () => dropdown.classList.remove('is-open'));

  // 应用已保存的主题
  try {
    const saved = localStorage.getItem('love_theme');
    if (saved) {
      const t = JSON.parse(saved);
      if (t.vars) Object.entries(t.vars).forEach(([k,v]) =>
        document.documentElement.style.setProperty(k, v)
      );
    }
  } catch(e) {}
})();

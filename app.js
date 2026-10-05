const $ = function (id) {
  return document.getElementById(id);
};

const urlInput = $('url');
const crawlBtn = $('crawl');
const resultBox = $('result');
const errorBox = $('error');

function setStatus(text, busy) {
  if (busy === undefined) busy = false;
  const statusEl = $('statusText');
  if (statusEl) statusEl.textContent = text;
  if (crawlBtn) crawlBtn.disabled = busy;
  const dot = document.querySelector('.status i');
  if (dot) dot.style.background = busy ? '#ffd166' : '#63e6a5';
}

function formatMs(val) {
  return typeof val === 'number' ? val + ' ms' : '';
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showError(msg) {
  errorBox.innerHTML = '<b>Could not safely extract this page.</b><div>' + escapeHtml(msg) + '</div>';
  errorBox.classList.remove('hidden');
  resultBox.classList.add('hidden');
}

async function run() {
  errorBox.classList.add('hidden');
  resultBox.classList.add('hidden');
  
  const latencyEl = $('latency');
  if (latencyEl) latencyEl.textContent = '...';
  
  setStatus('FETCHING', true);
  const startTime = performance.now();
  const timer = setInterval(function () {
    if (latencyEl) {
      latencyEl.textContent = formatMs(Math.round(performance.now() - startTime));
    }
  }, 50);

  let targetUrl = (urlInput.value || '').trim();
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = 'https://' + targetUrl;
    urlInput.value = targetUrl;
  }

  try {
    const response = await fetch('/api/crawler', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });
    const data = await response.json();
    
    if (latencyEl) {
      latencyEl.textContent = formatMs(Math.round(performance.now() - startTime));
    }

    if (!data.ok) {
      setStatus('BLOCKED / FAILED');
      if ($('fetchMs')) $('fetchMs').textContent = '-';
      if ($('parseMs')) $('parseMs').textContent = '-';
      if ($('quality')) $('quality').textContent = '-';
      if ($('method')) $('method').textContent = '-';
      showError((data.error && data.error.message) || 'Unknown crawler failure');
      return;
    }

    setStatus('COMPLETE');
    if ($('fetchMs')) $('fetchMs').textContent = formatMs(data.stages && data.stages.fetch_ms);
    if ($('parseMs')) {
      const p = (data.stages && data.stages.parse_ms) || 0;
      const e = (data.stages && data.stages.extraction_ms) || 0;
      $('parseMs').textContent = formatMs(p + e);
    }
    if ($('quality')) $('quality').textContent = data.quality + '/100';
    if ($('method')) $('method').textContent = data.method || '';
    if ($('title')) $('title').textContent = data.title || 'Untitled page';
    if ($('qualityBig')) $('qualityBig').textContent = data.quality;

    const link = $('finalUrl');
    if (link) {
      link.href = data.final_url || targetUrl;
      link.textContent = data.final_url || targetUrl;
    }

    const metaItems = [];
    if (data.word_count) metaItems.push(data.word_count.toLocaleString() + ' words');
    if (data.language) metaItems.push(data.language);
    if (data.content_type) metaItems.push(data.content_type);
    if (Array.isArray(data.warnings)) {
      for (let i = 0; i < data.warnings.length; i++) {
        metaItems.push(data.warnings[i]);
      }
    }

    const metaContainer = $('meta');
    if (metaContainer) {
      let metaHtml = '';
      for (let i = 0; i < metaItems.length; i++) {
        metaHtml += '<span>' + escapeHtml(metaItems[i]) + '</span>';
      }
      metaContainer.innerHTML = metaHtml;
    }

    if ($('content')) $('content').textContent = data.text || '';
    if ($('trace')) {
      $('trace').textContent = JSON.stringify(
        {
          quality: data.quality,
          method: data.method,
          latency_ms: data.latency_ms,
          stages: data.stages,
          warnings: data.warnings,
          final_url: data.final_url
        },
        null,
        2
      );
    }
    resultBox.classList.remove('hidden');
  } catch (err) {
    if (latencyEl) {
      latencyEl.textContent = formatMs(Math.round(performance.now() - startTime));
    }
    setStatus('ERROR');
    showError(err.message || 'Network error');
  } finally {
    clearInterval(timer);
    if (crawlBtn) crawlBtn.disabled = false;
  }
}

crawlBtn.addEventListener('click', run);
urlInput.addEventListener('keydown', function (e) {
  if (e.key === 'Enter') run();
});

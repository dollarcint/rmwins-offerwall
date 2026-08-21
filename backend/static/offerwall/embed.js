(() => {
  if (window.__rmwOfferwallEmbedReady) return;
  window.__rmwOfferwallEmbedReady = true;

  const frames = () => Array.from(document.querySelectorAll("iframe.rmw-offerwall-frame"));
  window.addEventListener("message", (event) => {
    if (!event.data || event.data.type !== "rmw:resize") return;
    const frame = frames().find((item) => item.contentWindow === event.source);
    if (!frame) return;
    let expectedOrigin;
    try {
      expectedOrigin = new URL(frame.src, document.baseURI).origin;
    } catch (error) {
      return;
    }
    if (event.origin !== expectedOrigin) return;
    if (event.data.appId !== frame.dataset.rmwAppId) return;
    const requestedHeight = Number(event.data.height);
    if (!Number.isFinite(requestedHeight)) return;
    const safeHeight = Math.max(600, Math.min(2400, Math.ceil(requestedHeight)));
    frame.height = String(safeHeight);
    frame.style.height = `${safeHeight}px`;
  });
})();
